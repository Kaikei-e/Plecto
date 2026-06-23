//! TLS termination config (ADR 000014): build a rustls `ServerConfig` from the manifest's
//! `[[tls]]` certs at load/reload. Cert selection is by SNI — a per-host cert, falling back to a
//! host-less default; if neither matches, the handshake is refused (no cert to present), which is
//! fail-closed. Building here (not in the server) means a bad cert aborts the whole build, so a
//! failed reload never swaps in a TLS config that cannot serve, and the config rides `ActiveConfig`
//! behind the same `ArcSwap` as the filter set. Sync rustls + the `ring` provider; the async
//! acceptor lives in `plecto-server`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::crypto::ring;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::error::ControlError;
use crate::manifest::TlsCert;

/// SNI cert selection (ADR 000014): a per-host cert map plus an optional default. `resolve` is
/// called by rustls during the handshake with the client's SNI; no match and no default → `None`,
/// and rustls fails the handshake (fail-closed — Plecto presents no cert it was not configured to).
#[derive(Debug)]
struct SniResolver {
    by_host: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        hello
            .server_name()
            .and_then(|name| self.by_host.get(&name.to_ascii_lowercase()))
            .cloned()
            .or_else(|| self.default.clone())
    }
}

/// The TLS configs built from `[[tls]]`: the TCP config (HTTP/1.1 + HTTP/2 via ALPN, ADR 000015)
/// and the QUIC config (HTTP/3, ADR 000016). Both share one SNI cert resolver, so a host's cert is
/// presented identically over TCP and QUIC.
pub(crate) struct TlsConfigs {
    /// HTTP/1.1 + HTTP/2 over TCP: ALPN `[h2, http/1.1]`, TLS 1.2 + 1.3.
    pub(crate) tcp: Arc<ServerConfig>,
    /// HTTP/3 over QUIC: ALPN `[h3]`, TLS 1.3 only.
    pub(crate) quic: Arc<ServerConfig>,
}

/// Build the TCP + QUIC TLS `ServerConfig`s from the manifest's `[[tls]]` entries, or `None` when
/// there are none (the server then serves plain HTTP/1.1, no h3). Any unreadable / unparsable /
/// duplicate cert is a fail-closed `ControlError` that aborts the caller's build (ADR 000014). The
/// TCP config advertises ALPN `[h2, http/1.1]` (h2 preferred, ADR 000015); the QUIC config
/// advertises `[h3]` and is TLS-1.3 only (QUIC mandates 1.3, RFC 9001). Both share one `SniResolver`.
pub(crate) fn build_server_configs(
    entries: &[TlsCert],
    base_dir: &Path,
) -> Result<Option<TlsConfigs>, ControlError> {
    if entries.is_empty() {
        return Ok(None);
    }

    let mut by_host: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut default: Option<Arc<CertifiedKey>> = None;
    for entry in entries {
        let certified = Arc::new(load_certified_key(entry, base_dir)?);
        match &entry.host {
            Some(host) => {
                if by_host
                    .insert(host.to_ascii_lowercase(), certified)
                    .is_some()
                {
                    return Err(tls_err(entry, "duplicate cert for this SNI host"));
                }
            }
            None => {
                if default.replace(certified).is_some() {
                    return Err(tls_err(entry, "more than one default (host-less) cert"));
                }
            }
        }
    }

    // One resolver, shared by both configs (Arc clone): SNI selects the same cert over TCP and QUIC.
    let resolver = Arc::new(SniResolver { by_host, default });

    // TCP: HTTP/1.1 + HTTP/2 via ALPN (h2 preferred, ADR 000015), TLS 1.2 + 1.3.
    let mut tcp = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(provider_init_err)?
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    tcp.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    // QUIC: HTTP/3, ALPN `h3`, TLS 1.3 only (ADR 000016). 0-RTT stays disabled: `max_early_data_size`
    // is left at its default 0, so the server refuses TLS early data. A gateway must not forward
    // early-data requests to upstreams that may not emit 425 (Too Early) (RFC 8470), so refusing it
    // outright is the only safe choice here.
    let mut quic = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(provider_init_err)?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    quic.alpn_protocols = vec![b"h3".to_vec()];

    Ok(Some(TlsConfigs {
        tcp: Arc::new(tcp),
        quic: Arc::new(quic),
    }))
}

/// A rustls provider/version init failure (not a per-cert fault) mapped to a fail-closed error.
fn provider_init_err(e: rustls::Error) -> ControlError {
    ControlError::TlsCert {
        host: None,
        path: String::new(),
        reason: format!("rustls provider init: {e}"),
    }
}

/// Read + parse one `[[tls]]` entry's PEM cert chain and private key into a `CertifiedKey`.
fn load_certified_key(entry: &TlsCert, base_dir: &Path) -> Result<CertifiedKey, ControlError> {
    let cert_chain = read_certs(entry, base_dir)?;
    if cert_chain.is_empty() {
        return Err(tls_err(entry, "no certificates in cert_path PEM"));
    }
    let key = read_key(entry, base_dir)?;
    let signing_key = ring::sign::any_supported_type(&key)
        .map_err(|e| tls_err(entry, &format!("unsupported private key: {e}")))?;
    Ok(CertifiedKey::new(cert_chain, signing_key))
}

fn read_certs(
    entry: &TlsCert,
    base_dir: &Path,
) -> Result<Vec<CertificateDer<'static>>, ControlError> {
    let bytes = std::fs::read(base_dir.join(&entry.cert_path))
        .map_err(|e| tls_err_path(entry, &entry.cert_path, &format!("read failed: {e}")))?;
    // PEM parsing lives in rustls-pki-types now (rustls-pemfile is unmaintained, RUSTSEC-2025-0134).
    CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| tls_err_path(entry, &entry.cert_path, &format!("bad cert PEM: {e}")))
}

fn read_key(entry: &TlsCert, base_dir: &Path) -> Result<PrivateKeyDer<'static>, ControlError> {
    let bytes = std::fs::read(base_dir.join(&entry.key_path))
        .map_err(|e| tls_err_path(entry, &entry.key_path, &format!("read failed: {e}")))?;
    // `from_pem_slice` returns the first private key, or a typed error if there is none / it is
    // malformed — so the previous "no key" branch folds into the error path.
    PrivateKeyDer::from_pem_slice(&bytes)
        .map_err(|e| tls_err_path(entry, &entry.key_path, &format!("bad key PEM: {e}")))
}

fn tls_err(entry: &TlsCert, reason: &str) -> ControlError {
    tls_err_path(entry, &entry.cert_path, reason)
}

fn tls_err_path(entry: &TlsCert, path: &str, reason: &str) -> ControlError {
    ControlError::TlsCert {
        host: entry.host.clone(),
        path: path.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh self-signed cert written to a temp dir, plus a host-less (default) `[[tls]]` entry.
    fn default_cert_entry() -> (tempfile::TempDir, TlsCert) {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, generated.cert.pem()).unwrap();
        std::fs::write(&key_path, generated.key_pair.serialize_pem()).unwrap();
        let entry = TlsCert {
            host: None,
            cert_path: cert_path.to_str().unwrap().to_string(),
            key_path: key_path.to_str().unwrap().to_string(),
        };
        (dir, entry)
    }

    #[test]
    fn builds_tcp_and_quic_configs_with_distinct_alpn() {
        let (dir, entry) = default_cert_entry();
        let configs = build_server_configs(&[entry], dir.path())
            .unwrap()
            .expect("a cert entry yields TCP + QUIC configs");
        // TCP advertises h2 then http/1.1 (ADR 000015); QUIC advertises only h3 (ADR 000016).
        assert_eq!(
            configs.tcp.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "TCP ALPN is h2 then http/1.1"
        );
        assert_eq!(
            configs.quic.alpn_protocols,
            vec![b"h3".to_vec()],
            "QUIC ALPN is h3 only"
        );
    }

    #[test]
    fn no_tls_entries_yields_none() {
        assert!(
            build_server_configs(&[], std::path::Path::new("."))
                .unwrap()
                .is_none(),
            "no [[tls]] means no TLS/QUIC configs (plain HTTP/1.1, no h3)"
        );
    }
}

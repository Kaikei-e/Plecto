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

/// Build the TLS `ServerConfig` from the manifest's `[[tls]]` entries, or `None` when there are
/// none (the server then serves plain HTTP/1.1). Any unreadable / unparsable / duplicate cert is
/// a fail-closed `ControlError` that aborts the caller's build (ADR 000014). ALPN advertises
/// `h2` then `http/1.1` (h2 preferred); the server serves HTTP/2 only when `h2` is negotiated,
/// HTTP/1.1 otherwise (ADR 000015 — h2 over TLS+ALPN only, no h2c).
pub(crate) fn build_server_config(
    entries: &[TlsCert],
    base_dir: &Path,
) -> Result<Option<Arc<ServerConfig>>, ControlError> {
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

    let resolver = Arc::new(SniResolver { by_host, default });
    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| ControlError::TlsCert {
            host: None,
            path: String::new(),
            reason: format!("rustls provider init: {e}"),
        })?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    // h2 first (preferred), http/1.1 second: a client that supports both gets HTTP/2; one that
    // only speaks http/1.1 still negotiates it. The server picks the protocol per the negotiated
    // ALPN (ADR 000015).
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Some(Arc::new(config)))
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

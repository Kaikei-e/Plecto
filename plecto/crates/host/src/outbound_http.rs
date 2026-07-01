//! The SSRF-guarded outbound connector (ADR 000036).
//!
//! This wires [`OutboundPolicy`] into `wasi:http/outgoing-handler` by implementing
//! [`WasiHttpHooks::send_request`] — the one seam wasmtime-wasi-http gives an embedder to own how an
//! outgoing request is sent. We deliberately do NOT call the crate's default connector, because it
//! dials `TcpStream::connect("host:port")` and never surfaces the resolved IP, so a hostname that
//! passes an allowlist but resolves to `127.0.0.1` / `169.254.169.254` would still be dialed.
//!
//! Our `send_request` enforces, in order:
//!   1. **Allowlist** (sync, deny-by-default) — an unlisted `(scheme, host, port)` is rejected with
//!      no DNS lookup and no socket, as `HttpRequestDenied`.
//!   2. **Concurrency bound** — a per-filter semaphore; over the cap is `ConnectionLimitReached`.
//!   3. **Resolve + classify + pin** (async, under the total deadline) — the host resolves the name
//!      itself, classifies *every* resolved address with the SSRF guard, rejects the whole request
//!      if any is blocked (`DestinationIpProhibited`), and connects to the vetted IP directly. This
//!      closes the DNS-rebinding TOCTOU window. TLS SNI / cert validation still use the original
//!      hostname.
//!   4. **Resource bounds** — connect timeout, whole-call `tokio::time::timeout` (the host-side I/O
//!      deadline epoch interruption cannot provide, ADR 000006 / 000036), and a response-body cap.
//!
//! Every denial reaches the guest as a `wasi:http` `error-code`, never a silent success — fail-closed.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use http_body_util::{BodyExt, Limited};
use hyper::{Request, Uri};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use wasmtime_wasi::runtime::AbortOnDropJoinHandle;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::p2::bindings::http::types::{DnsErrorPayload, ErrorCode};
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;
use wasmtime_wasi_http::p2::types::{
    HostFutureIncomingResponse, IncomingResponse, OutgoingRequestConfig,
};
use wasmtime_wasi_http::p2::{HttpResult, WasiHttpHooks, hyper_request_error};

use crate::outbound::{AddrVerdict, OutboundPolicy, Scheme};

/// Per-filter outbound state, held by the loaded filter and shared across its requests. The
/// semaphore lives here so the per-filter concurrency cap is genuinely shared, not per-request.
pub(crate) struct OutboundState {
    policy: Arc<OutboundPolicy>,
    permits: Arc<Semaphore>,
    resolver: Arc<Resolver>,
}

impl OutboundState {
    pub(crate) fn new(policy: OutboundPolicy) -> Self {
        let permits = Arc::new(Semaphore::new(policy.max_concurrent as usize));
        Self {
            policy: Arc::new(policy),
            permits,
            resolver: Arc::new(Resolver::System),
        }
    }

    /// A fresh hooks handle for one request/Store — cheap Arc clones over the shared state.
    pub(crate) fn hooks(&self) -> PlectoHttpHooks {
        PlectoHttpHooks {
            policy: self.policy.clone(),
            permits: self.permits.clone(),
            resolver: self.resolver.clone(),
        }
    }

    #[cfg(test)]
    fn new_with_resolver(policy: OutboundPolicy, resolver: Resolver) -> Self {
        let permits = Arc::new(Semaphore::new(policy.max_concurrent as usize));
        Self {
            policy: Arc::new(policy),
            permits,
            resolver: Arc::new(resolver),
        }
    }
}

/// The `WasiHttpHooks` implementation installed per Store. Enforces [`OutboundPolicy`] at the send
/// seam; keeps every other hook (forbidden headers, body chunking) at the crate default.
pub(crate) struct PlectoHttpHooks {
    policy: Arc<OutboundPolicy>,
    permits: Arc<Semaphore>,
    resolver: Arc<Resolver>,
}

impl PlectoHttpHooks {
    /// A hooks handle that denies every outbound call. Used for filters with no outbound policy —
    /// belt-and-suspenders, since those filters link no `wasi:http` and cannot reach this at all.
    pub(crate) fn deny_all() -> Self {
        Self {
            policy: Arc::new(OutboundPolicy {
                allow: Vec::new(),
                allow_private: Vec::new(),
                connect_timeout: Duration::from_secs(1),
                total_timeout: Duration::from_secs(1),
                max_response_bytes: 1,
                max_concurrent: 1,
            }),
            permits: Arc::new(Semaphore::new(1)),
            resolver: Arc::new(Resolver::System),
        }
    }
}

impl WasiHttpHooks for PlectoHttpHooks {
    fn send_request(
        &mut self,
        request: Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        // Never returns Err(HttpError): all denials are surfaced to the guest as a resolved
        // `error-code` future, which is the fail-closed, guest-observable outcome.
        Ok(self.dispatch(request, config))
    }
}

impl PlectoHttpHooks {
    fn dispatch(
        &mut self,
        request: Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HostFutureIncomingResponse {
        let use_tls = config.use_tls;
        let scheme = if use_tls { Scheme::Https } else { Scheme::Http };

        let Some((host, port)) = authority_of(&request, use_tls) else {
            return ready_err(ErrorCode::HttpRequestUriInvalid);
        };

        // 1. Allowlist: deny-by-default, before any DNS or socket work.
        if !self.policy.allows(scheme, &host, port) {
            return ready_err(ErrorCode::HttpRequestDenied);
        }

        // 2. Per-filter concurrency bound.
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            return ready_err(ErrorCode::ConnectionLimitReached);
        };

        // 3 + 4. Resolve, classify every address, pin, connect — all under the total deadline.
        let policy = self.policy.clone();
        let resolver = self.resolver.clone();
        let total = policy.total_timeout;
        let connect_timeout = policy.connect_timeout;
        let max_body = policy.max_response_bytes;

        let handle = wasmtime_wasi::runtime::spawn(async move {
            let _permit = permit; // held for the whole call, bounding concurrency
            let outcome = timeout(total, async move {
                let addrs = resolver.resolve(&host, port).await.map_err(|_| dns_err())?;
                if addrs.is_empty() {
                    return Err(dns_err());
                }
                // Verify EVERY resolved address; a legitimate endpoint resolves only to allowed
                // space. A mix (e.g. a rebinding A-record set) is rejected wholesale.
                for addr in &addrs {
                    if policy.classify(addr.ip()) != AddrVerdict::Allowed {
                        return Err(ErrorCode::DestinationIpProhibited);
                    }
                }
                connect_and_send(
                    addrs[0],
                    &host,
                    use_tls,
                    connect_timeout,
                    max_body,
                    total,
                    request,
                )
                .await
            })
            .await;
            let inner = outcome.unwrap_or(Err(ErrorCode::ConnectionTimeout));
            Ok::<_, wasmtime::Error>(inner)
        });

        HostFutureIncomingResponse::pending(handle)
    }
}

/// A resolved-error future the guest observes immediately (fail-closed).
fn ready_err(code: ErrorCode) -> HostFutureIncomingResponse {
    HostFutureIncomingResponse::ready(Ok(Err(code)))
}

fn dns_err() -> ErrorCode {
    ErrorCode::DnsError(DnsErrorPayload {
        rcode: None,
        info_code: None,
    })
}

/// Extract `(host, port)` from a request's authority, applying the scheme's default port.
fn authority_of(request: &Request<HyperOutgoingBody>, use_tls: bool) -> Option<(String, u16)> {
    let authority = request.uri().authority()?;
    let host = authority.host();
    if host.is_empty() {
        return None;
    }
    let port = authority
        .port_u16()
        .unwrap_or(if use_tls { 443 } else { 80 });
    Some((host.to_string(), port))
}

/// Connect to a pre-vetted, pinned address and send the request. `host` is the ORIGINAL hostname,
/// used only for the `Host` header and TLS SNI / certificate validation — never for connecting
/// (we dial `addr`), so DNS cannot be re-resolved to a different IP between check and connect.
#[allow(clippy::too_many_arguments)]
async fn connect_and_send(
    addr: SocketAddr,
    host: &str,
    use_tls: bool,
    connect_timeout: Duration,
    max_response_bytes: u64,
    between_bytes_timeout: Duration,
    mut request: Request<HyperOutgoingBody>,
) -> Result<IncomingResponse, ErrorCode> {
    // Set the Host header from the authority if the guest didn't. Compute the owned value first so
    // no borrow of `request` is held across the `headers_mut()` insert.
    let host_header = request
        .uri()
        .authority()
        .and_then(|a| hyper::header::HeaderValue::from_str(a.as_str()).ok());
    if !request.headers().contains_key(hyper::header::HOST)
        && let Some(value) = host_header
    {
        request.headers_mut().insert(hyper::header::HOST, value);
    }

    let tcp = timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(|_| ErrorCode::ConnectionRefused)?;
    let _ = tcp.set_nodelay(true);

    let (mut sender, worker) = if use_tls {
        let tls = tls_connect(host, tcp, connect_timeout).await?;
        handshake(TokioIo::new(tls), connect_timeout).await?
    } else {
        handshake(TokioIo::new(tcp), connect_timeout).await?
    };

    // origin-form: an HTTP/1.1 request line carries only path+query, not scheme/authority.
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    *request.uri_mut() = Uri::builder()
        .path_and_query(path)
        .build()
        .map_err(|_| ErrorCode::HttpRequestUriInvalid)?;

    let resp = sender
        .send_request(request)
        .await
        .map_err(hyper_request_error)?;

    // Cap the response body (CWE-770): a filter cannot make the host buffer an unbounded response.
    let resp = resp.map(|body| {
        Limited::new(body, max_response_bytes as usize)
            .map_err(move |_| ErrorCode::HttpResponseBodySize(Some(max_response_bytes)))
            .boxed_unsync()
    });

    Ok(IncomingResponse {
        resp,
        // Keep the connection-driver task alive for the response's lifetime; the handle aborts it on
        // drop. Dropping it here would kill the connection before the body is read.
        worker: Some(worker),
        between_bytes_timeout,
    })
}

/// Drive an established connection: spawn the connection future on a background task and return the
/// request sender plus the task handle (whose lifetime must span the response — it aborts on drop).
async fn handshake<S>(
    io: TokioIo<S>,
    connect_timeout: Duration,
) -> Result<
    (
        hyper::client::conn::http1::SendRequest<HyperOutgoingBody>,
        AbortOnDropJoinHandle<()>,
    ),
    ErrorCode,
>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = timeout(connect_timeout, hyper::client::conn::http1::handshake(io))
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(hyper_request_error)?;
    let worker = wasmtime_wasi::runtime::spawn(async move {
        let _ = conn.await;
    });
    Ok((sender, worker))
}

/// Build a TLS stream to the pinned TCP socket, validating the certificate against the ORIGINAL
/// hostname (SNI = `host`), not the pinned IP. Uses the workspace's ring provider explicitly, since
/// with both ring and aws-lc-rs linked there is no single process-default provider.
async fn tls_connect(
    host: &str,
    tcp: TcpStream,
    connect_timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ErrorCode> {
    use rustls::pki_types::ServerName;

    let config = client_config()?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let server_name = ServerName::try_from(host.to_string()).map_err(|_| dns_err())?;
    timeout(connect_timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(|_| ErrorCode::TlsProtocolError)
}

/// A process-wide rustls client config (webpki roots, ring provider), built once.
fn client_config() -> Result<Arc<rustls::ClientConfig>, ErrorCode> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    if let Some(cfg) = CFG.get() {
        return Ok(cfg.clone());
    }
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ErrorCode::TlsProtocolError)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let cfg = Arc::new(cfg);
    let _ = CFG.set(cfg);
    Ok(CFG.get().expect("just set").clone())
}

/// DNS resolver seam: the system resolver in production; a static map in tests so the
/// resolve→classify→pin decision can be exercised deterministically without real DNS.
enum Resolver {
    System,
    #[cfg(test)]
    Static(std::collections::HashMap<String, Vec<std::net::IpAddr>>),
}

impl Resolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ()> {
        match self {
            Resolver::System => tokio::net::lookup_host((host, port))
                .await
                .map(|it| it.collect())
                .map_err(|_| ()),
            #[cfg(test)]
            Resolver::Static(map) => Ok(map
                .get(host)
                .map(|ips| ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
                .unwrap_or_default()),
        }
    }
}

/// An empty outgoing body for requests without one (test helper).
#[cfg(test)]
fn empty_out_body() -> HyperOutgoingBody {
    use bytes::Bytes;
    use http_body_util::Empty;
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed_unsync()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::AllowEntry;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn cfg(use_tls: bool) -> OutgoingRequestConfig {
        OutgoingRequestConfig {
            use_tls,
            connect_timeout: Duration::from_secs(2),
            first_byte_timeout: Duration::from_secs(2),
            between_bytes_timeout: Duration::from_secs(2),
        }
    }

    fn test_policy(allow: Vec<AllowEntry>) -> OutboundPolicy {
        OutboundPolicy {
            allow,
            allow_private: vec![],
            connect_timeout: Duration::from_secs(2),
            total_timeout: Duration::from_secs(5),
            max_response_bytes: 64 * 1024,
            max_concurrent: 8,
        }
    }

    fn allow(host: &str, port: u16, scheme: Scheme) -> AllowEntry {
        AllowEntry {
            scheme,
            host: host.to_string(),
            port,
        }
    }

    fn req(uri: &str) -> Request<HyperOutgoingBody> {
        Request::builder().uri(uri).body(empty_out_body()).unwrap()
    }

    fn ready_code(fut: HostFutureIncomingResponse) -> ErrorCode {
        match fut {
            HostFutureIncomingResponse::Ready(Ok(Err(code))) => code,
            _ => panic!("expected a ready error future"),
        }
    }

    async fn pending_code(fut: HostFutureIncomingResponse) -> ErrorCode {
        match fut {
            HostFutureIncomingResponse::Pending(handle) => match handle.await {
                Ok(Ok(_)) => panic!("expected an error, got a response"),
                Ok(Err(code)) => code,
                Err(e) => panic!("task failed: {e}"),
            },
            _ => panic!("expected a pending future"),
        }
    }

    /// A minimal HTTP/1.1 server on loopback that returns `body` with a correct content-length.
    async fn spawn_server(body: Vec<u8>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                    let _ = sock.flush().await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn connect_and_send_plaintext_success() {
        let addr = spawn_server(b"hello".to_vec()).await;
        let request = req(&format!("http://{addr}/"));
        let resp = connect_and_send(
            addr,
            &addr.ip().to_string(),
            false,
            Duration::from_secs(2),
            1024,
            Duration::from_secs(5),
            request,
        )
        .await
        .expect("connect_and_send succeeds");
        assert_eq!(resp.resp.status(), 200);
        let bytes = resp.resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"hello");
    }

    #[tokio::test]
    async fn response_body_cap_is_enforced() {
        let addr = spawn_server(vec![b'x'; 100]).await;
        let request = req(&format!("http://{addr}/"));
        let resp = connect_and_send(
            addr,
            &addr.ip().to_string(),
            false,
            Duration::from_secs(2),
            10, // cap below the 100-byte body
            Duration::from_secs(5),
            request,
        )
        .await
        .expect("headers arrive before the body is read");
        let collected = resp.resp.into_body().collect().await;
        assert!(collected.is_err(), "a body over the cap must error");
    }

    #[tokio::test]
    async fn dispatch_denies_unlisted_host() {
        let policy = test_policy(vec![allow("authz.example.com", 443, Scheme::Https)]);
        let mut hooks = OutboundState::new(policy).hooks();
        let fut = hooks
            .send_request(req("https://evil.example.com/"), cfg(true))
            .unwrap();
        assert!(matches!(ready_code(fut), ErrorCode::HttpRequestDenied));
    }

    #[tokio::test]
    async fn dispatch_denies_wrong_scheme_and_port() {
        let policy = test_policy(vec![allow("authz.example.com", 443, Scheme::Https)]);
        let mut hooks = OutboundState::new(policy).hooks();
        // right host, wrong scheme (http vs the allowed https)
        let fut = hooks
            .send_request(req("http://authz.example.com/"), cfg(false))
            .unwrap();
        assert!(matches!(ready_code(fut), ErrorCode::HttpRequestDenied));
    }

    #[tokio::test]
    async fn dispatch_blocks_host_that_resolves_to_loopback() {
        // The core rebinding defense: an allowlisted NAME that resolves to a blocked IP is rejected
        // on the resolved address, even though a server is listening there.
        let live = spawn_server(b"secret".to_vec()).await;
        let policy = test_policy(vec![allow("authz.internal", live.port(), Scheme::Http)]);
        let resolver = Resolver::Static(HashMap::from([(
            "authz.internal".to_string(),
            vec![IpAddr::from([127, 0, 0, 1])],
        )]));
        let mut hooks = OutboundState::new_with_resolver(policy, resolver).hooks();
        let fut = hooks
            .send_request(
                req(&format!("http://authz.internal:{}/", live.port())),
                cfg(false),
            )
            .unwrap();
        assert!(matches!(
            pending_code(fut).await,
            ErrorCode::DestinationIpProhibited
        ));
    }

    #[tokio::test]
    async fn dispatch_denies_over_concurrency_limit() {
        let mut policy = test_policy(vec![allow("authz.internal", 80, Scheme::Http)]);
        policy.max_concurrent = 1;
        let state = OutboundState::new(policy);
        let mut hooks = state.hooks();
        // exhaust the single shared permit
        let _held = state.permits.clone().try_acquire_owned().unwrap();
        let fut = hooks
            .send_request(req("http://authz.internal/"), cfg(false))
            .unwrap();
        assert!(matches!(ready_code(fut), ErrorCode::ConnectionLimitReached));
    }
}

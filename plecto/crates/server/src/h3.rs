//! HTTP/3 (ADR 000016).
//!
//! An independent QUIC/UDP listener terminates HTTP/3, then feeds each request into the SAME
//! `proxy_core` as the TCP path — only the wire transport and the body adapters differ. The request
//! body (the h3 recv stream) is wrapped as an `http_body::Body` so it streams to the upstream, and
//! the response body streams back out over the h3 send stream. RFC 9114 forbids connection-specific
//! headers in HTTP/3 messages; `headers_to_vec`/`copy_headers` already strip the hop-by-hop set both
//! ways, so what we send over h3 is compliant.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use hyper::{Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;

use crate::proxy::proxy_core;
use crate::respond::synth;
use crate::{BoxError, MAX_CONCURRENT_STREAMS, ServerState};

/// Build the QUIC `Endpoint` for HTTP/3 from control's QUIC TLS config, bound on the same port
/// number as the TCP listener (UDP). Caps concurrent request streams (see below).
pub(crate) fn build_h3_endpoint(
    quic_cfg: Arc<plecto_control::TlsServerConfig>,
    tcp_addr: SocketAddr,
) -> anyhow::Result<quinn::Endpoint> {
    let crypto = QuicServerConfig::try_from(quic_cfg)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    // Cap concurrent request streams per connection (mirrors ADR 000015's h2 cap): each h3 request
    // is one bidi stream → one chain dispatch, so this bounds one connection's draw on the M1 pool
    // and is defence-in-depth against stream-flood DoS. uni streams (h3 control / QPACK) keep
    // quinn's default. quinn itself enforces QUIC's 3x anti-amplification limit (RFC 9000 §8/§21),
    // so the endpoint can't be turned into a UDP reflector with a spoofed source address.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(MAX_CONCURRENT_STREAMS.into());
    server_config.transport_config(Arc::new(transport));
    // Same port as the TCP listener, but UDP — an independent protocol namespace.
    let udp_addr = SocketAddr::new(tcp_addr.ip(), tcp_addr.port());
    Ok(quinn::Endpoint::server(server_config, udp_addr)?)
}

/// Accept QUIC connections, set up an h3 connection on each, and drive every request stream through
/// `handle_h3_request`. A per-connection / per-request error is logged, never fatal.
pub(crate) async fn serve_h3(state: Arc<ServerState>, endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        // Count a QUIC connection against the same global cap as TCP.
        let permit = match state.conn_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return, // semaphore closed → stop accepting
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when this connection task ends
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %e, "QUIC connection failed");
                    return;
                }
            };
            // the client's address, captured before `conn` is moved into the h3 wrapper — fed to
            // `proxy_core` for X-Forwarded-For (ADR 000018), same as the TCP `accept()` peer.
            let peer = conn.remote_address();
            let mut h3conn = match h3::server::Connection::<h3_quinn::Connection, Bytes>::new(
                h3_quinn::Connection::new(conn),
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %e, "h3 connection setup failed");
                    return;
                }
            };
            loop {
                match h3conn.accept().await {
                    Ok(Some(resolver)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_h3_request(state, peer, resolver).await {
                                tracing::debug!(error = %e, "h3 request failed");
                            }
                        });
                    }
                    // graceful close (the client sent GOAWAY / closed the connection).
                    Ok(None) => break,
                    Err(e) => {
                        tracing::debug!(error = %e, "h3 accept failed");
                        break;
                    }
                }
            }
        });
    }
}

/// Handle one HTTP/3 request: split the bidi stream, wrap the recv half as the request body, run
/// the shared `proxy_core` (scheme is always `https` — h3 is always over TLS), then stream the
/// response head + body back over the send half.
async fn handle_h3_request(
    state: Arc<ServerState>,
    peer: SocketAddr,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
) -> anyhow::Result<()> {
    let (req, stream) = resolver.resolve_request().await?;
    let (mut send, recv) = stream.split();
    let (parts, ()) = req.into_parts();
    let body = H3ReqBody { recv }.boxed();

    let resp = match proxy_core(state, "https", peer, parts, body).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "h3 fast-path error");
            synth(StatusCode::BAD_GATEWAY, "upstream", b"upstream error")
        }
    };

    let (rparts, mut rbody) = resp.into_parts();
    send.send_response(Response::from_parts(rparts, ())).await?;
    while let Some(frame) = rbody.frame().await {
        match frame {
            Ok(f) => {
                if let Ok(data) = f.into_data() {
                    send.send_data(data).await?;
                }
            }
            Err(e) => {
                // a mid-stream upstream body error: stop here and finish the stream.
                tracing::debug!(error = %e, "h3 response body error");
                break;
            }
        }
    }
    send.finish().await?;
    Ok(())
}

/// Adapts an HTTP/3 request's recv stream into an `http_body::Body`, so the request body streams to
/// the upstream like any other inbound body. One copy per chunk into `Bytes` (the recv buffer's
/// own type is opaque); the body is otherwise opaque pass-through.
struct H3ReqBody {
    recv: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
}

impl Body for H3ReqBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        match this.recv.poll_recv_data(cx) {
            Poll::Ready(Ok(Some(mut buf))) => {
                let bytes = buf.copy_to_bytes(buf.remaining());
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(None),
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(Box::new(e)))),
            Poll::Pending => Poll::Pending,
        }
    }
}

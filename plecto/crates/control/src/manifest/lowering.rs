//! Lower a manifest `FilterEntry` into the host's `LoadOptions` (ADR 000006).

use plecto_host::LoadOptions;

#[cfg(feature = "outbound-http")]
use super::SchemeKind;
use super::{FilterEntry, IsolationKind};

impl FilterEntry {
    /// The host `LoadOptions` for this entry: isolation plus any metering overrides
    /// (ADR 000006). Unset knobs keep the host defaults.
    pub(crate) fn load_options(&self) -> LoadOptions {
        let mut opts = match self.isolation {
            IsolationKind::Trusted => LoadOptions::trusted(),
            IsolationKind::Untrusted => LoadOptions::untrusted(),
        };
        if let Some(ms) = self.init_deadline_ms {
            opts = opts.with_init_deadline_ms(ms);
        }
        if let Some(ms) = self.request_deadline_ms {
            opts = opts.with_request_deadline_ms(ms);
        }
        if let Some(bytes) = self.max_memory_bytes {
            opts = opts.with_max_memory_bytes(bytes);
        }
        if let Some(rl) = self.ratelimit {
            opts = opts.with_ratelimit_bucket(rl.capacity, rl.refill_tokens, rl.refill_interval_ms);
        }
        #[cfg(feature = "outbound-http")]
        if let Some(ob) = &self.outbound {
            // Validated already (`validate`), so the CIDR parses and the allowlist is non-empty.
            let allow = ob
                .allow
                .iter()
                .map(|d| plecto_host::AllowEntry {
                    scheme: match d.scheme {
                        SchemeKind::Https => plecto_host::Scheme::Https,
                        SchemeKind::Http => plecto_host::Scheme::Http,
                    },
                    host: d.host.clone(),
                    port: d.port.unwrap_or_else(|| d.scheme.default_port()),
                })
                .collect();
            opts = opts.with_outbound(
                allow,
                ob.allow_private.clone(),
                ob.connect_timeout_ms,
                ob.total_timeout_ms,
                ob.max_response_bytes,
                ob.max_concurrent,
            );
        }
        opts
    }
}

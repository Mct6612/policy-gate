// crates/firewall-proxy-wasm/src/lib.rs — Proxy-Wasm Filter for LLM Security
//
// Safety Action SA-060: Export high-security firewall to WASM for Proxy-Wasm.
// Compatible with Envoy, Kong, and APISIX.
#![deny(clippy::all)]

use firewall_core::{
    config::FirewallConfig, evaluate_raw_for_tenant, init_with_config, next_sequence,
};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

/// Maximum allowed request body size (64 KiB). Bodies larger than this are
/// rejected with HTTP 413 before any evaluation occurs (DoS prevention).
const MAX_BODY_BYTES: usize = 65_536;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(FirewallRootContext {
            config: FirewallConfig::default(),
        })
    });
}

// ─── Root Context (Configuration) ───────────────────────────────────────────

struct FirewallRootContext {
    config: FirewallConfig,
}

impl Context for FirewallRootContext {}

impl RootContext for FirewallRootContext {
    fn on_configure(&mut self, _config_size: usize) -> bool {
        // get_plugin_configuration returns Option<Vec<u8>> in proxy-wasm 0.2.x.
        let config_bytes: Option<Vec<u8>> = self.get_plugin_configuration();

        if let Some(bytes) = config_bytes {
            if let Ok(config_str) = std::str::from_utf8(&bytes) {
                match FirewallConfig::from_toml_str(config_str) {
                    Ok(cfg) => {
                        self.config = cfg;
                        // Initialize core with the injected config.
                        // SA-XXX: The token is baked into the WASM at build time.
                        let token = env!("POLICY_GATE_INIT_TOKEN");
                        if let Err(e) = init_with_config(token, self.config.clone()) {
                            log::error!("Firewall initialization failed: {:?}", e);
                            return false;
                        }
                        log::info!(
                            "Firewall initialized successfully via Proxy-Wasm configuration."
                        );
                        return true;
                    }
                    // FIX 14: Return false on TOML parse failure — fail closed, not open.
                    Err(e) => {
                        log::error!(
                            "Failed to parse TOML configuration: {}. \
                             Refusing to start with unknown policy.",
                            e
                        );
                        return false;
                    }
                }
            }
        }
        log::warn!("Using default firewall configuration (fail-closed fallback).");
        true
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(FirewallHttpContext {
            request_buffer: Vec::new(),
            tenant_id: None,
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

// ─── HTTP Context (Filtering) ───────────────────────────────────────────────

struct FirewallHttpContext {
    request_buffer: Vec<u8>,
    tenant_id: Option<String>,
}

impl Context for FirewallHttpContext {}

impl HttpContext for FirewallHttpContext {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        self.tenant_id = self.get_http_request_header("x-tenant-id");
        Action::Continue
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        // FIX 9: Pause until the full body is available. In proxy-wasm, body_size
        // is cumulative; reading from offset 0 on each intermediate call would
        // duplicate every earlier chunk. We read exactly once at end_of_stream.
        if !end_of_stream {
            return Action::Pause;
        }

        // FIX 13: Reject oversized bodies before reading (DoS prevention).
        if body_size > MAX_BODY_BYTES {
            self.send_http_response(
                413,
                vec![("Content-Type", "application/json")],
                Some(b"{\"error\": \"Request body too large\"}"),
            );
            return Action::Continue;
        }

        // FIX 9: Read the complete body once, now that end_of_stream is true.
        if let Some(body) = self.get_http_request_body(0, body_size) {
            self.request_buffer = body;
        }

        // FIX 12: Reject non-UTF-8 request bodies instead of silently normalising
        // them with from_utf8_lossy, which could allow encoding-bypass attacks.
        let body_str = match String::from_utf8(self.request_buffer.clone()) {
            Ok(s) => s,
            Err(_) => {
                self.send_http_response(
                    400,
                    vec![("Content-Type", "application/json")],
                    Some(b"{\"error\": \"Invalid UTF-8 in request body\"}"),
                );
                return Action::Continue;
            }
        };

        // FIX 10: Use next_sequence() instead of the hardcoded literal 0 so that
        // each request gets a unique, monotonically increasing sequence number,
        // preserving the integrity of the HMAC audit chain.
        let verdict = evaluate_raw_for_tenant(body_str, next_sequence(), self.tenant_id.clone());

        if !verdict.is_pass() {
            let reason = verdict
                .audit
                .block_reason
                .as_ref()
                .map(|r| format!("{:?}", r))
                .unwrap_or_else(|| "Unknown Security Violation".to_string());

            log::warn!("[BLOCK] Security Violation: {}", reason);

            // FIX 11: Serialise `reason` through serde_json so that quotes and
            // backslashes in the Debug output are properly escaped, preventing
            // hand-built JSON from becoming malformed or injectable.
            let reason_json =
                serde_json::to_string(&reason).unwrap_or_else(|_| "\"unknown\"".to_string());
            let body = format!(
                r#"{{"error": "Security Violation", "reason": {}}}"#,
                reason_json
            );

            self.send_http_response(
                403,
                vec![("Content-Type", "application/json")],
                Some(body.as_bytes()),
            );
            return Action::Pause;
        }

        Action::Continue
    }

    fn on_http_response_body(&mut self, _body_size: usize, _end_of_stream: bool) -> Action {
        // Egress filtering can be added here if needed.
        Action::Continue
    }
}

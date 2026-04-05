// crates/firewall-proxy-wasm/src/lib.rs — Proxy-Wasm Filter for LLM Security
//
// Safety Action SA-060: Export high-security firewall to WASM for Proxy-Wasm.
// Compatible with Envoy, Kong, and APISIX.

use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use firewall_core::{evaluate_raw_for_tenant, init_with_config, config::FirewallConfig};

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
        // get_plugin_configuration returns Option<Vec<u8>> in 0.2.x
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
                        log::info!("Firewall initialized successfully via Proxy-Wasm configuration.");
                        return true;
                    }
                    Err(e) => {
                        log::error!("Failed to parse TOML configuration from plugin config: {}", e);
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
        if body_size > 0 {
            if let Some(chunk) = self.get_http_request_body(0, body_size) {
                self.request_buffer.extend_from_slice(&chunk);
            }
        }

        if !end_of_stream {
            return Action::Pause;
        }

        // Full body received - Evaluate
        let body_str = String::from_utf8_lossy(&self.request_buffer);
        
        // Use evaluate_raw_for_tenant for multi-tenant matching
        let verdict = evaluate_raw_for_tenant(body_str.to_string(), 0, self.tenant_id.clone());

        if !verdict.is_pass() {
            let reason = verdict.audit.block_reason.as_ref()
                .map(|r| format!("{:?}", r))
                .unwrap_or_else(|| "Unknown Security Violation".to_string());
            
            log::warn!("[BLOCK] Security Violation: {}", reason);
            
            self.send_http_response(
                403,
                vec![("Content-Type", "application/json")],
                Some(format!(r#"{{"error": "Security Violation", "reason": "{}"}}"#, reason).as_bytes()),
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

//! firewall-proxy — standalone HTTP reverse proxy for policy-gate
//!
//! Drop-in replacement for direct LLM API calls. Evaluates every request
//! through the firewall-core safety gate before forwarding to the upstream.
//!
//! # Environment variables
//!
//! | Variable                     | Default                                    | Purpose                                      |
//! |------------------------------|--------------------------------------------|----------------------------------------------|
//! | PORT                         | 8080                                       | Listening port                               |
//! | UPSTREAM_URL                 | https://api.openai.com/v1/chat/completions | Target LLM API (OpenAI, Anthropic, Ollama …) |
//! | CONFIG_RELOAD_INTERVAL_SECS  | 30                                         | How often to poll firewall.toml for changes  |
//!
//! # Hot-reload
//!
//! The proxy polls `firewall.toml` every `CONFIG_RELOAD_INTERVAL_SECS` seconds.
//! A `POST /reload` endpoint triggers an immediate reload on demand.
//! Only changed configs are applied; invalid configs are rejected (old config stays active).
//!
//! # Streaming
//!
//! Requests with `"stream": true` are rejected with HTTP 400. Streaming output
//! prevents the egress safety check from running on the complete response before
//! it reaches the client, violating the fail-closed egress guarantee.

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use reqwest::Client;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

use firewall_core::{
    evaluate_for_tenant, evaluate_output_for_tenant, next_sequence, try_reload_config, PromptInput,
};

// ─── Shared state ─────────────────────────────────────────────────────────────

struct AppState {
    http_client: Client,
    upstream_url: String,
    metrics_handle: PrometheusHandle,
}

// ─── Startup ──────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Prometheus metrics — exposed via /metrics on the main axum router
    let metrics_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus metrics recorder");

    info!("Metrics available at /metrics on the proxy port");

    // Firewall init
    info!("Initializing policy-gate firewall core...");
    if let Err(e) = firewall_core::init() {
        error!("Failed to initialize firewall: {}", e);
        std::process::exit(1);
    }
    info!("Firewall initialized successfully.");

    // Config from environment
    let upstream_url = std::env::var("UPSTREAM_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string());

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("PORT must be a valid port number");

    // Hot-reload: background task that polls firewall.toml for changes
    let reload_interval_secs: u64 = std::env::var("CONFIG_RELOAD_INTERVAL_SECS")
        .unwrap_or_else(|_| "30".to_string())
        .parse()
        .unwrap_or(30);

    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(reload_interval_secs));
        ticker.tick().await; // skip immediate first tick
        loop {
            ticker.tick().await;
            run_reload();
        }
    });

    let state = Arc::new(AppState {
        http_client: Client::new(),
        upstream_url,
        metrics_handle,
    });

    let app = Router::new()
        .route("/v1/chat/completions", post(handle_chat_completion))
        .route("/health", get(|| async { "OK" }))
        .route("/metrics", get(metrics_handler))
        .route("/reload", post(reload_handler))
        .layer(DefaultBodyLimit::max(1024 * 1024 * 10)) // 10 MB
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Proxy listening on {}", addr);
    info!("Config hot-reload every {}s | POST /reload for immediate reload", reload_interval_secs);
    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ─── Request handler ──────────────────────────────────────────────────────────

async fn handle_chat_completion(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    let start = Instant::now();

    // Track every incoming request
    counter!("policy_gate_requests_total").increment(1);

    // 1. Reject streaming — egress safety cannot be guaranteed on partial chunks
    if payload.get("stream").and_then(|s| s.as_bool()).unwrap_or(false) {
        warn!("Rejected streaming request (not supported).");
        counter!("policy_gate_streaming_rejected_total").increment(1);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": {
                    "message": "policy-gate proxy does not support stream: true. \
                                Streaming output prevents the egress safety check from running \
                                on the complete response before delivery to the client.",
                    "type": "invalid_request_error",
                }
            })),
        )
            .into_response();
    }

    // 2. Extract message content for evaluation
    let combined_messages = extract_message_content(&payload);
    if combined_messages.is_empty() {
        counter!("policy_gate_blocked_total", "reason" => "empty_content").increment(1);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": {"message": "No messages found or empty content.", "type": "invalid_request_error"}})),
        )
            .into_response();
    }

    // 3. Build PromptInput (NFKC normalisation + size check)
    let prompt_input = match PromptInput::new(&combined_messages) {
        Ok(pi) => pi,
        Err(block_reason) => {
            warn!("Ingress blocked (malformed input): {:?}", block_reason);
            counter!("policy_gate_blocked_total", "reason" => "malformed_input").increment(1);
            record_latency_ms("ingress_block", &start);
            return blocked_response("malformed_input", &format!("{block_reason:?}"));
        }
    };

    // 4. Ingress evaluation
    let tenant_id = headers.get("x-tenant-id").and_then(|h| h.to_str().ok());
    info!(
        "Evaluating ingress prompt ({} bytes) for tenant: {:?}",
        combined_messages.len(),
        tenant_id.unwrap_or("anonymous")
    );
    let sequence = next_sequence();
    let verdict = evaluate_for_tenant(prompt_input.clone(), sequence, tenant_id);

    if !verdict.is_pass() {
        let reason = verdict
            .audit
            .block_reason
            .as_ref()
            .map(|r| format!("{r:?}"))
            .unwrap_or_else(|| format!("{:?}", verdict.kind));
        warn!("Ingress blocked: {:?}", verdict.kind);
        counter!("policy_gate_blocked_total", "reason" => "ingress_policy").increment(1);
        counter!("policy_gate_verdicts_total", "verdict" => "block").increment(1);
        record_latency_ms("ingress_block", &start);
        return blocked_response("policy_violation", &reason);
    }

    counter!("policy_gate_verdicts_total", "verdict" => "pass").increment(1);

    // 5. Forward to upstream
    info!("Forwarding to upstream: {}", state.upstream_url);
    let mut upstream_req = state.http_client.post(&state.upstream_url).json(&payload);
    if let Some(auth) = headers.get("authorization") {
        upstream_req = upstream_req.header("authorization", auth.clone());
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            error!("Upstream request failed: {}", e);
            counter!("policy_gate_upstream_errors_total").increment(1);
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": {"message": "Failed to reach upstream API.", "type": "upstream_error"}})),
            )
                .into_response();
        }
    };

    let upstream_status = upstream_resp.status();
    let resp_json: Value = match upstream_resp.json().await {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": {"message": "Invalid JSON from upstream."}})),
            )
                .into_response();
        }
    };

    if !upstream_status.is_success() {
        return (upstream_status, Json(resp_json)).into_response();
    }

    // 6. Egress evaluation on the response content
    if let Some(response_text) = extract_response_content(&resp_json) {
        info!("Evaluating egress response...");
        match evaluate_output_for_tenant(&prompt_input, &response_text, sequence, tenant_id) {
            Ok(egress_verdict) => {
                if !egress_verdict.is_pass() {
                    warn!("Egress blocked: {:?}", egress_verdict.kind);
                    counter!("policy_gate_blocked_total", "reason" => "egress_policy").increment(1);
                    counter!("policy_gate_verdicts_total", "verdict" => "egress_block")
                        .increment(1);
                    record_latency_ms("egress_block", &start);
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": {
                                "message": "Response blocked by policy-gate egress checks (leakage or PII detected).",
                                "type": "egress_violation",
                            }
                        })),
                    )
                        .into_response();
                }
            }
            Err(e) => {
                error!("Egress evaluation error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": {"message": "Internal egress evaluation error."}})),
                )
                    .into_response();
            }
        }
    }

    // 7. All clear — return upstream response to caller
    record_latency_ms("pass", &start);
    (upstream_status, Json(resp_json)).into_response()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Concatenate all message `content` fields from an OpenAI-style payload.
fn extract_message_content(payload: &Value) -> String {
    let mut out = String::new();
    if let Some(msgs) = payload.get("messages").and_then(|m| m.as_array()) {
        for msg in msgs {
            if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                out.push_str(content);
                out.push('\n');
            }
        }
    }
    out
}

/// Extract the first choice's message content from an OpenAI-style response.
fn extract_response_content(resp: &Value) -> Option<String> {
    resp.get("choices")?
        .as_array()?
        .first()?
        .get("message")?
        .get("content")?
        .as_str()
        .map(|s| s.to_string())
}

/// Record request latency as a Prometheus histogram (milliseconds).
fn record_latency_ms(outcome: &'static str, start: &Instant) {
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    histogram!("policy_gate_request_duration_ms", "outcome" => outcome).record(elapsed);
}

/// Build a unified 403 Forbidden response for blocked requests.
fn blocked_response(error_type: &str, details: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": {
                "message": "Prompt blocked by policy-gate.",
                "type": error_type,
                "details": details,
            }
        })),
    )
        .into_response()
}

/// Serve Prometheus metrics in text exposition format.
async fn metrics_handler(State(state): State<Arc<AppState>>) -> Response {
    let body = state.metrics_handle.render();
    (StatusCode::OK, [( "content-type", "text/plain; version=0.0.4")], body).into_response()
}

// ─── Hot-reload ───────────────────────────────────────────────────────────────

/// Shared reload logic — called by both the background poller and the HTTP handler.
fn run_reload() {
    match try_reload_config() {
        Ok(true) => {
            info!("firewall.toml reloaded — new config is now active.");
            counter!("policy_gate_config_reloads_total", "result" => "changed").increment(1);
        }
        Ok(false) => {
            // No changes detected — nothing to do, don't log to avoid noise.
        }
        Err(e) => {
            warn!("Config reload failed (old config remains active): {}", e);
            counter!("policy_gate_config_reloads_total", "result" => "error").increment(1);
        }
    }
}

/// `POST /reload` — trigger an immediate reload of firewall.toml.
///
/// Returns 200 if the config was reloaded or was already up-to-date.
/// Returns 500 if the new config was invalid (old config remains active).
async fn reload_handler() -> Response {
    match try_reload_config() {
        Ok(true) => {
            info!("Manual reload via POST /reload — new config active.");
            counter!("policy_gate_config_reloads_total", "result" => "changed").increment(1);
            (StatusCode::OK, Json(json!({"status": "reloaded", "message": "New config is now active."}))).into_response()
        }
        Ok(false) => {
            (StatusCode::OK, Json(json!({"status": "unchanged", "message": "firewall.toml has not changed."}))).into_response()
        }
        Err(e) => {
            warn!("Manual reload failed: {}", e);
            counter!("policy_gate_config_reloads_total", "result" => "error").increment(1);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"status": "error", "message": e}))).into_response()
        }
    }
}

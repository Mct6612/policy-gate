# Standalone Reverse Proxy

`policy-gate` ships a standalone HTTP reverse proxy (`crates/firewall-proxy`) built on `axum`. Drop it in front of any LLM API — no code changes required.

## Quickstart

```bash
# Start with defaults (port 8080, targets OpenAI)
cargo run --release -p firewall-proxy

# Fully configured:
export UPSTREAM_API_KEY="sk-..."
export UPSTREAM_URL="https://api.openai.com/v1/chat/completions"
export PORT=8080
cargo run --release -p firewall-proxy
```

Point your application's `baseURL` at `http://localhost:8080/v1`.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Proxy listening port |
| `UPSTREAM_URL` | `https://api.openai.com/v1/chat/completions` | Target LLM API |
| `UPSTREAM_API_KEY` | empty | Bearer token forwarded to upstream |
| `CONFIG_RELOAD_INTERVAL_SECS` | `30` | Polling interval for `firewall.toml` hot-reload |

## Request flow

```text
App → POST /v1/chat/completions
  → [ingress: policy-gate evaluate]
  → 403 if blocked  ─────────────────────────── (never reaches internet)
  → forward to UPSTREAM_URL
  → [egress: policy-gate evaluate_output]
  → 403 if PII / leakage detected
  → 200 + response to App
```

> **Streaming:** By default, requests with `"stream": true` are rejected (HTTP 400). Compile with `--features streaming-egress` to enable stateful Aho-Corasick scanning across SSE chunks.

## Prometheus metrics

The `/metrics` endpoint is served in Prometheus text format, restricted to loopback callers.

```bash
curl http://localhost:8080/metrics
```

| Metric | Labels | Description |
|---|---|---|
| `policy_gate_requests_total` | — | All incoming requests |
| `policy_gate_verdicts_total` | `verdict=pass\|block\|egress_block` | Decision distribution |
| `policy_gate_blocked_total` | `reason=ingress_policy\|egress_policy\|malformed_input\|empty_content` | Block reason breakdown |
| `policy_gate_streaming_rejected_total` | — | Rejected streaming requests |
| `policy_gate_upstream_errors_total` | — | Upstream API connection failures |
| `policy_gate_streaming_egress_blocks_total` | — | Connections aborted by egress match |
| `policy_gate_request_duration_ms` | `outcome=pass\|ingress_block\|egress_block` | End-to-end latency histogram |

Example scrape config:

```yaml
scrape_configs:
  - job_name: policy-gate-proxy
    static_configs:
      - targets: ["localhost:8080"]
    metrics_path: /metrics
```

## Hot-reload

The proxy polls `firewall.toml` every `CONFIG_RELOAD_INTERVAL_SECS` seconds. Trigger an immediate reload:

```bash
curl -X POST http://localhost:8080/reload
# {"status":"reloaded","message":"New config is now active."}
```

If the new config is invalid, the reload is rejected and the old config stays active (staged validation, zero downtime).

## Management CLI

```bash
cargo build --release -p firewall-cli
./target/release/firewall-cli --help
```

| Command | Description |
|---|---|
| `validate <file>` | Syntax + RegexSet compatibility check |
| `diff <file1> <file2>` | Structural diff — added/removed rules and settings |
| `eval` | Line-by-line evaluation from stdin |
| `reload <dir> [--token TOKEN]` | Hot-reload multi-tenant configs from a directory |

```bash
# Diff two configs
firewall-cli diff firewall.example.toml firewall.toml

# Production reload
POLICY_GATE_INIT_TOKEN=secret firewall-cli reload /etc/policy-gate/tenants/
```

## Docker

```bash
docker build -t policy-gate:latest \
  --build-arg POLICY_GATE_INIT_TOKEN=$(openssl rand -hex 32) .

docker run -p 8080:8080 \
  -e UPSTREAM_URL="https://api.openai.com/v1/chat/completions" \
  policy-gate:latest
```

## Kubernetes (Helm)

```bash
helm install policy-gate ./helm/policy-gate \
  --set proxy.upstreamUrl="https://api.openai.com/v1/chat/completions" \
  --set proxy.initToken="YOUR_SECURE_TOKEN"
```

The Helm chart handles HA replicas, ConfigMap-based hot-reload, non-root security context, and Prometheus health checks.

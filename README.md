# policy-gate

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Safety](https://img.shields.io/badge/safety-experimental-yellow.svg)](SAFETY_MANUAL.md)

Deterministic firewall for LLM applications, agents, and AI gateways.

Instead of trying to guess whether a prompt is dangerous, `policy-gate` only permits explicitly allowlisted intents. Unknown, ambiguous, or policy-violating inputs fail closed.

It is designed for teams that want predictable enforcement, auditable decisions, and a narrow control boundary around model access.

**Status:** Experimental — under active development. Not certified for production use.  
**Note:** This project borrows architectural ideas from functional safety engineering, but it is not an IEC 61508 implementation and makes no certification or compliance claims.

## At a glance

- deterministic allowlist-first enforcement
- fail-closed behavior on ambiguity, disagreement, or fault
- auditable PASS/BLOCK outcomes
- **Multi-Tenant Policy Hub**: isolated security profiles per tenant
- **shadow mode**: safe deployment and observability without active blocking
- advisory heuristics and expanded **Fast-Semantic 2.0** analysis (8 attack centroids) kept outside the safety path
- optional session-aware analysis for multi-turn escalation patterns
- **[experimental] Streaming Egress**: safe Aho-Corasick chunk scanning across SSE boundaries
- **configurable voter strictness per tenant**: `on_diagnostic_agreement = "fail_closed"` for high-sensitivity workflows
- **[new] Contextual Anchor Validation (SA-080)**: prevents egress bypass by enforcing output constraints based on ingress intent (e.g. TextOnly vs CodePermitted)
- Rust core with Node, Python, WASM, and **Proxy-Wasm** targets

## Best fit

`policy-gate` is a good fit when only a small, well-defined set of user intents should ever reach a model or downstream toolchain.

Typical examples:

- fronting an agent that can call tools or execute multi-step workflows
- enforcing tenant- or profile-specific prompt policies
- validating model output for prompt leakage, credential leakage, or PII
- creating a reviewable PASS/BLOCK layer in front of LLM APIs
- detecting multi-turn escalation attempts across conversation turns

It is a weaker fit for broad, open-ended chatbot moderation or any workflow where the allowed intent space is large and fluid.

## Why this approach

Most AI guardrails are probabilistic classifiers. They can be useful, but they are often hard to reason about, hard to audit, and difficult to bound in high-control environments.

`policy-gate` takes a narrower approach:

- allow only known-good intent shapes
- block unknown or ambiguous requests by default
- keep the safety path deterministic
- treat heuristic and semantic analysis as advisory, not authoritative
- produce audit records for every decision

For narrow workflows, it is often better to make unsafe requests unrepresentable than to estimate whether they look risky.

## Guarantees and non-goals

What `policy-gate` aims to provide:

- deterministic PASS/BLOCK behavior on the core safety path
- fail-closed handling for ambiguity, disagreement, and internal faults
- reviewable audit output for each decision
- optional advisory analysis that never overrides the core verdict

What it does not aim to be:

- a general-purpose conversational safety layer
- a replacement for policy design, threat modeling, or human review
- a certification-grade safety system
- a claim of IEC 61508 compliance

## Quick example

import { Firewall } from "policy-gate";

// Initialize with a secret token for production-grade security
const firewall = await Firewall.createWithToken({
  token: process.env.FIREWALL_TOKEN,
  onAudit: async (entry) => {
    console.log(`[Audit] Tenant: ${entry.tenantId}, Sequence: ${entry.sequence}`);
    await db.audit.insert(entry);
  },
});

// Multi-tenant evaluation
const verdict = await firewall.evaluateForTenant(
  "tenant-a",
  "What is the capital of France?"
);

if (!verdict.isPass) {
  throw new Error(`Blocked by ${verdict.blockReason} for tenant-a`);
}
```

### Session-aware evaluation

```ts
import { Firewall } from "policy-gate";

const firewall = await Firewall.create({
  onAudit: (entry) => console.log(entry),
});

// Evaluate within a session context to detect multi-turn patterns
const verdict = await firewall.evaluateWithSession(
  "user-session-123",
  "How do I access the system configuration?"
);

if (verdict.sessionAnalysis.riskLevel === "High") {
  console.warn("High escalation risk detected in session!");
  // The session layer provides detailed indicators:
  // - PolicyTesting: Repeated similar prompts (Jaccard similarity > 0.8)
  // - TopicDrift: Abrupt shifts in user intent
  // - PayloadFragmentation: Suspected split payloads (e.g., unmatched braces)
}
```

## Pillars of safety

1.  **Deterministic Path**: The core safety function uses FSMs and rule engines, not probabilistic models.
2.  **Diverse Redundancy**: A 1oo2D voter ensures that even if one channel fails or has a gap, the system remains safe (fail-closed).
3.  **Normalisation-First**: All inputs are normalised (NFKC, homoglyph mapping, separator stripping) before evaluation.
4.  **Session-Aware Monitor**: Detects multi-turn escalation patterns like payload fragmentation and policy probing.
5.  **Multi-Tenant Hub**: Isolated security profiles and per-tenant audit logs for SaaS environments.
6.  **Pillar 6 Streaming Egress**: Safe Aho-Corasick chunk scanning across SSE boundaries.
7.  **SA-080 Contextual Anchoring**: Cross-pillar intent persistence ensures egress content matches ingress expectations.
  onAudit: async (entry) => {
    await db.audit.insert(entry);
  },
});

// Optional session-aware evaluation for multi-turn conversations
const sessionId = "user-123";
const verdict = await firewall.evaluateWithSession(
  sessionId,
  "How can I bypass security restrictions?"
);

if (!verdict.isPass) {
  console.log(`Blocked: ${verdict.blockReason}`);
  console.log(`Session risk: ${verdict.sessionAnalysis?.riskLevel}`);
  console.log(`Escalation score: ${verdict.sessionAnalysis?.escalationScore}`);
}

// Session statistics
const stats = firewall.getSessionStats();
console.log(`Active sessions: ${stats.activeSessions}`);
console.log(`High-risk sessions: ${stats.highRiskSessions}`);
```

### Python

```python
import policy_gate

# Multi-tenant initialization: loads all .toml configs from a directory
policy_gate.init_multi_tenant_registry(
    token="your-secret-token",
    dir_path="/etc/policy-gate/tenants/"
)

# Evaluate a request for a specific tenant
verdict = policy_gate.evaluate_raw_for_tenant(
    raw="What is the capital of France?",
    sequence=123,
    tenant_id="customer-a"
)

if not verdict["is_pass"]:
    raise RuntimeError(f"Blocked: {verdict['block_reason']}")
```

### Standalone Reverse Proxy (Zero-Code Integration)

For environments where deploying an integrated library is not feasible, `policy-gate` ships a standalone HTTP reverse proxy (`crates/firewall-proxy`) built on `axum`.

```bash
# Start with defaults (port 8080, targets OpenAI)
cargo run --release -p firewall-proxy

# Or fully configured:
export UPSTREAM_URL="https://api.openai.com/v1/chat/completions"
export PORT=8080
cargo run --release -p firewall-proxy
```

Then point your application's `baseURL` at `http://localhost:8080/v1` — no code changes required.

#### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Proxy listening port |
| `UPSTREAM_URL` | `https://api.openai.com/v1/chat/completions` | Target LLM API (OpenAI, Anthropic, Ollama, …) |
| `CONFIG_RELOAD_INTERVAL_SECS` | `30` | Polling interval for `firewall.toml` hot-reload |

#### Request flow

```text
App → POST /v1/chat/completions
  → [ingress: policy-gate evaluate]
  → 403 if blocked  ──────────────────────────────────── (never reaches internet)
  → forward to UPSTREAM_URL
  → [egress: policy-gate evaluate_output]
  → 403 if PII / leakage detected
  → 200 + response to App
```

> [!WARNING]
> **Streaming constraints:** By default, the `firewall-proxy` rejects requests containing `"stream": true` with HTTP 400. However, when compiled with `--features streaming-egress`, the proxy supports stateful Aho-Corasick scanning across SSE chunks. This enables safe streaming while maintaining fail-closed egress guarantees (with small latency trade-off for the overlap buffer).

#### Observability — Prometheus metrics

The proxy exposes a `/metrics` endpoint in Prometheus text exposition format on the same port:

```bash
curl http://localhost:8080/metrics
```

Available metrics:

| Metric | Labels | Description |
|---|---|---|
| `policy_gate_requests_total` | — | All incoming requests |
| `policy_gate_verdicts_total` | `verdict=pass\|block\|egress_block` | Decision distribution |
| `policy_gate_blocked_total` | `reason=ingress_policy\|egress_policy\|malformed_input\|empty_content` | Block reason breakdown |
| `policy_gate_streaming_rejected_total` | — | Rejected streaming requests |
| `policy_gate_upstream_errors_total` | — | Upstream API connection failures |
| `policy_gate_streaming_egress_blocks_total` | — | Total connections aborted due to egress pattern match |
| `policy_gate_request_duration_ms` | `outcome=pass|ingress_block|egress_block` | End-to-end latency histogram |

Example Prometheus scrape config:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: policy-gate-proxy
    static_configs:
      - targets: ["localhost:8080"]
    metrics_path: /metrics
```

#### Hot-reload — live config updates without restart

The proxy polls `firewall.toml` every `CONFIG_RELOAD_INTERVAL_SECS` seconds (default: 30).
A `POST /reload` endpoint triggers an immediate reload on demand:

```bash
# Trigger immediate reload (e.g. after editing firewall.toml)
curl -X POST http://localhost:8080/reload
# {"status":"reloaded","message":"New config is now active."}
```

> [!IMPORTANT]
> **Staged Validation (Pre-flight):** If the new `firewall.toml` contains an invalid regex or broken config, the reload is **rejected** and the old config stays active. The proxy will return HTTP 500 with a detailed validation error list. This ensures zero downtime even if an operator pushes a malformed policy.

#### Management CLI

The project includes `firewall-cli`, a powerful utility for policy governance and CI/CD integration.

```bash
# Build the management tool
cargo build --release -p firewall-cli
./target/release/firewall-cli --help
```

- **`validate <file>`**: Deep-validation of a config file. Checks syntax and `RegexSet` compatibility.
- **`diff <file1> <file2>`**: Structural comparison of two policies. Highlights added/removed rules, exceptions, and changed settings.
- **`eval`**: Standard line-by-line evaluation from stdin (useful for benchmarks).
- **`reload <dir> [--token TOKEN]`**: Hot-reload multi-tenant configurations from a directory. Staged validation ensures zero downtime; failures keep the previous config active. Supports `POLICY_GATE_INIT_TOKEN` for production authentication.

Example reload:
```bash
# Reload all tenant configs from directory (development)
firewall-cli reload ./policy-hub/

# Production reload with token authentication
POLICY_GATE_INIT_TOKEN=secret firewall-cli reload /etc/policy-gate/tenants/
```

Example diff:
```bash
firewall-cli diff firewall.example.toml firewall.toml
```

- **RegexSet Matching**: Migration to $O(1)$ scaling ensures that latency does not grow with the number of allowlist entries.
- **LRU Caching**: verdicts for normalized inputs are cached in a thread-safe LRU (default 1,000 capacity).

---

## Multi-Tenant Policy Hub (Pillar 5)

`policy-gate` supports complete isolation between multiple tenants, each with their own security profile.

- **Per-Tenant Configuration**: Each tenant can have its own `forbidden_keywords`, `permitted_intents`, and `context_window`.
- **Fail-Closed Isolation**: Requests are blocked by default if the `tenant_id` is unknown or if anonymous access is disabled.
- **Unified Registry**: Manage hundreds of tenants via a single directory of `.toml` files.

### Directory-based Registry

To load multiple tenants from a directory at startup:

```rust
// Rust
policy_gate::init_multi_tenant_registry(
    "your-secret-init-token",
    "/etc/policy-gate/tenants/"
).expect("Failed to load tenant registry");
```

Each `.toml` file in the directory defines one tenant. The filename (minus `.toml`) is used as the `tenant_id` unless explicitly overridden in the file.

### Evaluating with Tenant Context

Pass the `tenant_id` to the evaluation API to ensure the correct policy is applied:

```typescript
const verdict = await firewall.evaluateForTenant(
  "customer-123",
  "Question: How do I bypass the login?"
);
```
- **Sub-millisecond latency**: Cache hits are served in <100µs. Sequential throughput reaches **250+ req/s** on modern hardware.
- **Enterprise Hardening (Pillars 1-3)**: Implementation of staged hot-reloads, $O(1)$ matching, and semantic enforcement thresholds.

Reload events are tracked by the `policy_gate_config_reloads_total{result="changed|error"}` Prometheus counter.

## Deployment (Enterprise Ready)

`policy-gate` is designed for production reliability and can be deployed using standard DevOps tooling.

### Docker

A multi-stage, hardened Docker image is provided. To build it, you **must** provide the `POLICY_GATE_INIT_TOKEN`:

```bash
docker build -t policy-gate:latest \
  --build-arg POLICY_GATE_INIT_TOKEN=$(openssl rand -hex 32) .
```

Run the container:
```bash
docker run -p 8080:8080 \
  -e UPSTREAM_URL="https://api.openai.com/v1/chat/completions" \
  policy-gate:latest
```

### Kubernetes (Helm)

For scalable enterprise deployments, use the provided Helm chart:

```bash
# Install with custom values
helm install policy-gate ./helm/policy-gate \
  --set proxy.upstreamUrl="https://api.openai.com/v1/chat/completions" \
  --set proxy.initToken="YOUR_SECURE_TOKEN"
```

The Helm chart automatically handles:
- **High Availability:** Multiple replicas with anti-affinity.
- **Config Management:** `firewall.toml` is managed via ConfigMap and hot-reloaded.
- **Security:** Running as a non-root user with a read-only root filesystem.
- **Monitoring:** Integrated health checks and Prometheus support.
## High-throughput workloads

### Node.js (async / concurrent)

The Node.js bindings use napi-rs, which automatically runs evaluations on worker threads:

```ts
import { Firewall } from "policy-gate";

const firewall = await Firewall.create();

// Concurrent evaluation - napi-rs handles parallelism automatically
const prompts = [
  "What is the capital of France?",
  "Write a function",
  "Hello!"
];

const results = await Promise.all(
  prompts.map(p => firewall.evaluate(p))
);
```

### Rust (parallel batch)

Enable the `parallel` feature for batch evaluation with Rayon:

```toml
# Cargo.toml
firewall-core = { path = "./crates/firewall-core", features = ["parallel"] }
```

```rust
use firewall_core::evaluate_batch_parallel;

let prompts = vec![
    "What is the capital of France?".to_string(),
    "Write a function".to_string(),
];

let results = evaluate_batch_parallel(prompts, 0);
```

### Setup BERT for Semantic Analysis (Optional)

If you want to use the ML-based BERT mode for Channel D, run the setup script:

```bash
pip install huggingface_hub
python scripts/setup_bert.py
```

This will automatically check your `firewall.toml` and download the necessary model files from HuggingFace to the `models/` directory.

### Performance & Benchmarking

The core safety function is designed for ultra-low latency:

- **Sequential**: 250+ req/s (sub-ms cache hits, ~3-4ms cold)
- **Parallel (Rayon)**: scales with CPU cores (1,000+ req/s on 8-core)
- **Node.js async**: handled by napi-rs worker threads

## How it works

At a high level, the firewall:

1. normalizes and hardens the input before policy evaluation
2. evaluates it through independent deterministic channels
3. votes fail-closed on disagreements or faults
4. records an audit entry for review and analytics
5. can also validate model output against leakage and PII rules

## Architecture at a glance

```text
prompt
  -> normalization and structural hardening
  -> Channel A: FSM + allowlist matching
  -> Channel B: rule engine
  -> 1oo2-inspired fail-closed voter
  -> PASS / BLOCK + audit record
  -> Channel C advisory analysis (post-verdict, non-authoritative)
  -> Channel D semantic similarity (optional, advisory-only)
```

For egress validation, the same philosophy is applied to model responses through a separate two-channel path focused on leakage, framing patterns, and PII-like output.

## Design principles

- Deterministic safety path: the verdict does not depend on an LLM.
- Fail closed: unknowns, disagreements, and internal faults block.
- Channel diversity: the main channels use different techniques to reduce common-mode failure.
- Advisory isolation: heuristic and semantic signals never override the safety decision.
- Auditable operation: every decision can be recorded and analyzed later.
- Init authorization: build-time token prevents race-to-init attacks; no default secrets in source code.

## Main components

### Channel A: FSM + allowlist

Channel A is a finite state machine with explicit tokenization, forbidden-pattern checks, and allowlist matching. It includes a watchdog and returns `Fault` on deadline violations, which the voter treats as `Block`.

### Channel B: Rule engine

Channel B performs structural and lexical analysis without regex or ML in its core rule path. Block rules are evaluated before allow rules.

### Channel C: advisory heuristics

This channel runs after the verdict and stores non-authoritative heuristics in the audit trail. It is useful for operator review, investigation, and tuning, but it does not gate the decision.

### Channel D: semantic similarity (Fast-Semantic 2.0)

This is an optional high-performance semantic layer:

- **128-dimensional sparse embeddings** using FN-1a 4-gram salted hashing.
- **Ultra-low latency**: Benchmarked at **~31µs** per prompt (no ML runtime overhead).
- **Consolidated Corpus**: 200+ learned attack centroids derived from AdvBench + JailbreakBench.
- **Dual-Threshold Logic**:
  - `semantic_threshold` (default 0.70): Triggers advisory tagging (Pass with 'SemanticViolation' tag).
  - `semantic_enforce_threshold` (default 1.0): Triggers an automated BLOCK for high-confidence matches.
- **CI Tripwire**: Centroid hash verification ensures semantic-boundary changes are detected and reviewed.

*See `scripts/generate_centroids.py` for the training pipeline.*

### Egress firewall

The output side validates model responses against the original prompt and checks for leakage, framing signals, and PII-like content. It uses a two-channel fail-closed design separate from the ingress path.

#### Streaming Egress (Pillar 6)

For high-concurrency streaming applications, `policy-gate` provides a stateful Aho-Corasick scanner (`StreamScanner`) that operates across SSE chunk boundaries.
- **Overlap Buffer**: Maintains a 256-byte tail of the previous chunk to detect patterns split across packets.
- **Fail-Closed Teardown**: If a forbidden pattern is detected mid-stream, the proxy immediately:
    1. Sends a final SSE error event.
    2. Aborts the TCP connection (`RST_STREAM`) to prevent the browser from rendering the leaked chunk.
- **Config**: Toggle via `streaming_egress_enabled` in `firewall.toml`.

## Why it feels different from typical guardrails

- It is closer to a policy firewall than a prompt classifier.
- It optimizes for narrow, explainable control boundaries rather than broad conversational flexibility.
- It is designed around reviewability, diagnostics, and regression testing.
- It treats semantic analysis as support tooling, not as the safety kernel.

## Who it is for

- teams building agents with tool use or multi-step workflows
- platform engineers adding a control layer in front of LLM APIs
- security-minded builders who prefer deterministic policy enforcement
- researchers exploring deterministic guardrail architectures

## Project layout

```text
policy-gate/
├── crates/
│   ├── firewall-core/     # Rust safety kernel
│   ├── firewall-cli/      # CLI for benchmarks and verification flows
│   ├── firewall-napi/     # Node native binding
│   ├── firewall-pyo3/     # Python binding
│   ├── firewall-wasm/     # WASM / edge target
│   ├── firewall-proxy-wasm/ # Proxy-Wasm / Envoy target
│   └── firewall-fuzz/     # fuzz targets
├── scripts/               # smoke + conformance scripts
├── verification/          # Z3 models, corpora, analytics, benchmarks
├── deployment.md          # deployment notes
├── SAFETY_MANUAL.md       # deeper design and safety documentation
└── firewall.example.toml  # example configuration
```

## Supported runtimes

- Rust core library
- Node.js via `napi-rs`
- Python via `PyO3` and `maturin`
- WASM / edge builds

The safety function lives in Rust. The Node and Python packages are bindings around that core.

## Quickstart

### Node / TypeScript

```bash
npm install
npm run build:native
npm run build
npm run smoke
npm run conformance
```

Notes:

- `npm run build:native` builds the `firewall-napi` module and copies it to `native/index.node`.
- `npm run build` compiles [index.ts](./index.ts).
- `npm run smoke` exercises the basic wrapper paths.
- `npm run conformance` runs the shared corpus in [verification/conformance_corpus.json](./verification/conformance_corpus.json).

If the native `.node` file is not present yet, the wrapper falls back to a deterministic development stub.

### Python

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install maturin
python -m maturin develop --manifest-path crates/firewall-pyo3/Cargo.toml
python scripts/smoke.py
python scripts/conformance.py
```

If you prefer wheel-based installation:

```powershell
python -m pip install maturin
python -m maturin build --manifest-path crates/firewall-pyo3/Cargo.toml
$wheel = (Get-ChildItem .\target\wheels\*.whl | Select-Object -First 1).FullName
python -m pip install $wheel
python scripts\smoke.py
python scripts\conformance.py
```

### Rust core

```bash
cargo test -p firewall-core
cargo clippy -p firewall-core -- -D warnings
```

### Semantic feature compile check

```bash
cargo check -p firewall-core --features semantic
```

### Performance benchmarks

```bash
# All benchmarks
cargo bench -p firewall-core

# Individual benchmark groups
cargo bench -p firewall-core --bench channel_a    # FSM + allowlist
cargo bench -p firewall-core --bench channel_b    # Rule engine
cargo bench -p firewall-core --bench voter        # 1oo2D decision logic
cargo bench -p firewall-core --bench integration  # Full pipeline
cargo bench -p firewall-core --bench normalise   # Unicode normalization
```

See [`crates/firewall-core/BENCHMARKS.md`](crates/firewall-core/BENCHMARKS.md) for detailed benchmark documentation.

### WASM / edge

The workspace includes `crates/firewall-wasm` for edge and browser-oriented builds where the semantic feature remains disabled.

## API surface

The Rust core exposes APIs for:

- single prompt evaluation
- raw input evaluation
- multi-message conversation evaluation
- output / egress evaluation
- profile-based initialization
- audit review tracking

The bindings expose matching subsets of that behavior for Node and Python.

## Configuration and profiles

The project supports:

- default and profile-based initialization
- custom intent patterns
- tenant-specific policy configuration
- TOML-based configuration via [firewall.example.toml](./firewall.example.toml)

The design is multi-tenant at the policy layer and single-tenant at the safety decision core.

### Voter Strictness Per Tenant

By default, when both channels agree a prompt is safe but disagree on the matched intent (`DiagnosticAgreement`), the request is allowed through and queued for operator review.

For tenants processing **financial data, PII, or healthcare records**, any intent ambiguity is unacceptable. Set `on_diagnostic_agreement = "fail_closed"` to escalate these events to a hard Block:

```toml
# policy-hub/tenants/finance-prod.toml
tenant_id = "finance-prod"
allow_anonymous_tenants = false
on_diagnostic_agreement = "fail_closed"
audit_detail_level = "detailed"
semantic_enforce_threshold = 0.85
```

| Value | Behaviour | Recommended for |
|---|---|---|
| `pass_and_log` | Allow through, queue for 72h review (default) | General tenants |
| `fail_closed` | Escalate `DiagnosticAgreement` to `Block` | Finance, PII, healthcare |

### Policy-Hub - Fertige TOML-Profile

Das Projekt enthält einen Policy-Hub mit vorkonfigurierten Profilen für typische Use-Cases:

**Profile:**
- [`policy-hub/profiles/research-agent/firewall.toml`](policy-hub/profiles/research-agent/firewall.toml) - Für Research-Agenten mit erweiterten Egress-Kontrollen
- [`policy-hub/profiles/code-assistant/firewall.toml`](policy-hub/profiles/code-assistant/firewall.toml) - Für Code-Assistenten mit Code-spezifischen Regeln
- [`policy-hub/profiles/customer-support/firewall.toml`](policy-hub/profiles/customer-support/firewall.toml) - Für Kundenservice mit PII-Schutz

**Presets:**
- [`policy-hub/presets/strict.toml`](policy-hub/presets/strict.toml) - Maximal restriktiv
- [`policy-hub/presets/permissive.toml`](policy-hub/presets/permissive.toml) - Minimal restriktiv

Detaillierte Dokumentation: [`policy-hub/README.md`](policy-hub/README.md)

## Verification and testing

Verification is a major part of the project rather than an afterthought.

### Automated checks in the repo

- Rust test suite for core behavior and regressions
- smoke and conformance checks for Node and Python bindings
- fuzz targets in `crates/firewall-fuzz`
- dataset regressions for harmful prompts
- false-positive rate measurement
- CI security auditing with `cargo-audit`

### Formal verification

The repository includes Z3 models for critical invariants:

- [verification/channel_a.smt2](./verification/channel_a.smt2)
- [verification/voter.smt2](./verification/voter.smt2)
- [verification/rule_engine.smt2](./verification/rule_engine.smt2)

Run them with:

```bash
python verification/run_proofs.py
```

There is also a pattern-change tripwire:

```bash
python verification/check_pattern_hash.py
```

### Regression datasets

```bash
cargo build --release -p firewall-cli
python verification/benchmark_datasets.py
python verification/fp_rate_test.py
```

### Review and analytics tooling

The repository includes operator-facing support tooling with a full **Git-Ops automation loop**:

| Tool | Description |
|---|---|
| [operator_review.py](./verification/operator_review.py) | Interactive CLI for reviewing `DiagnosticDisagreement` events — with clustering, Z3 dry-run, and Git-Ops auto-commit |
| [suggest_pattern.py](./verification/suggest_pattern.py) | Generates regex patterns, SMT2 proof obligations, and Safety Manual snippets |
| [fuzz_regex.py](./verification/fuzz_regex.py) | Bypass fuzzer — combines allowlist regex with SQLi/XSS/PromptInjection payloads to detect over-permissive patterns |
| [disagreement_analytics.py](./verification/disagreement_analytics.py) | Batch analytics and FP rate reporting |
| [operator_review_architecture.md](./verification/operator_review_architecture.md) | Architecture notes and integration checklist |

**Operator workflow (one keypress `y` = full release cycle):**
```
False Positive → [R]/[S] → Z3 Dry-Run → Fuzz Check → Accept → TOML Patch → Safety Manual → git commit
```

## Hardening themes

The codebase contains explicit hardening work for areas such as:

- prompt injection markers and chat-template abuse
- obfuscation via Unicode confusables, combining marks, bidi controls, and separators
- low-and-slow probing detection through analytics
- watchdog behavior and fail-closed fault handling
- leakage and PII-like output validation
- audit integrity via chained HMAC-based records
- **session-aware multi-turn escalation detection** with sliding window memory
- **zero-trust verification of user-generated Regex via Z3 SMT2 Dry-Runs** (Shift-Left)
- **Git-Ops automation loop**: operator acceptance auto-patches `firewall.toml`, `SAFETY_MANUAL.md`, and creates a traceable `git commit`
- **automated regex bypass fuzzing**: `fuzz_regex.py` generates SQLi/XSS/PromptInjection probes against new allowlist patterns before they are committed

For the full design history and safety action log, see [SAFETY_MANUAL.md](./SAFETY_MANUAL.md).

## Limitations

`policy-gate` is intentionally narrow.

- It is not a general-purpose conversational safety solution.
- It works best when the allowed intent space is small and explicit.
- A deterministic allowlist-first design trades flexibility for predictability.
- Advisory semantic analysis is helpful, but it is not the trust anchor.
- The project is still under development and not appropriate for production or safety-critical deployment.

## When to use it

Use it when you want:

- a strict policy gate in front of model access
- deterministic PASS/BLOCK behavior
- auditable decisions and review workflows
- a defense-oriented wrapper around tool-using agents
- **multi-turn conversation protection** against escalation attacks

It is a weaker fit when you want:

- broad open-ended chatbot moderation
- nuanced intent classification over a large unconstrained prompt space
- a drop-in replacement for human review or policy design

## Related docs

- [SAFETY_MANUAL.md](./SAFETY_MANUAL.md)
- [deployment.md](./deployment.md)
- [RED_TEAM.md](./RED_TEAM.md)

## License

Apache License 2.0. See [LICENSE](./LICENSE).

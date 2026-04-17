# policy-gate

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Safety](https://img.shields.io/badge/safety-experimental-yellow.svg)](SAFETY_MANUAL.md)

**Deterministic policy firewall for LLMs.**  
Allowlist-first, fail-closed, fully auditable.  
Built for agents, tool-use pipelines, and SaaS multi-tenant deployments.

```ts
import { Firewall } from "policy-gate";

const fw = await Firewall.create();
const verdict = await fw.evaluateForTenant("tenant-a", "What is the capital of France?");

if (!verdict.isPass) throw new Error(`Blocked: ${verdict.blockReason}`);
```

**Status:** Experimental — do not use for safety-critical production.

---

## Why not a classifier?

Most AI guardrails are probabilistic. They estimate risk — and can be wrong in both directions.

`policy-gate` takes the opposite approach: **only explicitly allowlisted intents pass**. Everything unknown, ambiguous, or disagreed-upon fails closed. The verdict never depends on an LLM or a probability score.

---

## Core features

| | |
|---|---|
| **Deterministic allowlist enforcement** | Only known-good intent shapes pass. Unknown = Block. |
| **Fail-closed voter (1oo2)** | Two independent channels must agree. Disagreement or fault → Block. |
| **Ingress + Egress firewall** | Validates both prompts and model responses (leakage, PII, framing). |
| **Multi-tenant policy hub** | Isolated profiles, configs, and audit logs per tenant. |
| **Shadow mode** | Evaluate without blocking — safe for rollout and observability. |
| **Proxy mode** | Drop-in reverse proxy in front of any LLM API. Zero code changes. |

### Optional / advanced features

- **Streaming egress** `[experimental]` — Aho-Corasick scanning across SSE chunk boundaries
- **Fast-Semantic 2.0** `[optional]` — sparse embeddings + learned centroid corpus, ~31µs, advisory-only
- **Session-aware monitor** — multi-turn escalation detection (fragmentation, probing, topic drift)
- **Contextual Anchor Validation (SA-080)** — egress output constraints derived from ingress intent

---

## How it works

```
   App ──► policy-gate ingress ──────────────────────────────► Upstream LLM
              │                                                      │
              │  normalize                                           │
              │  Channel A: FSM + allowlist ──┐                     │
              │  Channel B: rule engine  ─────┴─► voter ──► PASS    │
              │                                   (fault/disagree → BLOCK + audit)
              │                                                      │
   App ◄── policy-gate egress ◄───────────────────────────────────-─┘
              │  Output Channel 1: pattern/PII scan ──┐
              │  Output Channel 2: framing / anchor ──┴─► voter ──► PASS / BLOCK
```

**Ingress channels (A + B)** — independent techniques, diverse by design to prevent common-cause failure.  
**Voter** — any disagreement, unknown result, or internal fault → Block.  
**Channel C** `[advisory]` — heuristic scoring after the verdict, never changes the outcome.  
**Channel D** `[optional]` — semantic similarity, advisory-only.

---

## Quickstart

### Node / TypeScript

```bash
npm install
npm run build:native   # builds Rust → native/index.node
npm run build          # compiles TypeScript
npm run smoke          # basic sanity check
npm run conformance    # full corpus
```

### Python

```bash
python -m venv .venv && .venv\Scripts\activate
pip install maturin
python -m maturin develop --manifest-path crates/firewall-pyo3/Cargo.toml
python scripts/smoke.py
python scripts/conformance.py
```

### Proxy (zero-code integration)

```bash
export UPSTREAM_URL="https://api.openai.com/v1/chat/completions"
export UPSTREAM_API_KEY="sk-..."
cargo run --release -p firewall-proxy
# → point your app at http://localhost:8080/v1
```

### Rust core

```bash
cargo test -p firewall-core
cargo clippy -p firewall-core -- -D warnings
```

---

## Configuration

Copy [`firewall.example.toml`](./firewall.example.toml) to `firewall.toml` and adjust.

Key settings:

```toml
# Only these intents may pass
permitted_intents = ["QuestionFactual", "TaskCodeGeneration"]

# Block any ambiguous intent for high-sensitivity tenants
on_diagnostic_agreement = "fail_closed"

# Optional: explicit tool allowlist for agentic workflows
allowed_tools = ["weather_tool", "calculator_tool"]

# Shadow mode: evaluate but never block (for rollout)
shadow_mode = true
```

---

## Project layout

```text
policy-gate/
├── crates/
│   ├── firewall-core/       # Rust safety kernel
│   ├── firewall-proxy/      # Standalone reverse proxy (axum)
│   ├── firewall-cli/        # Policy governance CLI
│   ├── firewall-napi/       # Node.js binding (napi-rs)
│   ├── firewall-pyo3/       # Python binding (PyO3 / maturin)
│   ├── firewall-wasm/       # WASM / edge target
│   └── firewall-proxy-wasm/ # Proxy-Wasm / Envoy target
├── docs/                    # Extended documentation (see below)
├── policy-hub/              # Pre-built TOML profiles and presets
├── verification/            # Z3 models, corpora, benchmarks, operator tooling
└── firewall.example.toml
```

---

## What this is NOT

- not a general-purpose moderation classifier
- not a jailbreak detector or prompt toxicity scorer
- not a replacement for human policy design and threat modeling
- not a certification-grade safety system or IEC 61508 implementation

---

## Design inspiration

`policy-gate` borrows ideas from functional safety engineering — fail-closed behavior, channel diversity, explicit fault handling. It is **not** an IEC 61508 implementation, has not been assessed by any third party, and makes no compliance claims. See [SAFETY_MANUAL.md](./SAFETY_MANUAL.md) for the full design rationale.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE).

---

## Further reading

| | |
|---|---|
| [SAFETY_MANUAL.md](./SAFETY_MANUAL.md) | Full design, hazard analysis, channel specs, safety requirements |
| [docs/proxy.md](./docs/proxy.md) | Reverse proxy, Prometheus metrics, hot-reload, CLI, Docker, Helm |
| [docs/multi-tenant.md](./docs/multi-tenant.md) | Tenant registry, profiles, voter strictness |
| [docs/agents.md](./docs/agents.md) | Tool-schema validation, LangGraph integration |
| [docs/performance.md](./docs/performance.md) | Benchmarks, parallel batch, BERT semantic mode |
| [docs/verification.md](./docs/verification.md) | Z3 proofs, regression datasets, operator review tooling |

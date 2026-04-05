# Product: policy-gate (firewall-core)

`policy-gate` is a deterministic firewall for LLM applications, agents, and AI gateways. Instead of classifying whether a prompt is dangerous, it only permits explicitly allowlisted intents — unknown, ambiguous, or policy-violating inputs fail closed.

It evaluates LLM input/output through a redundant 1oo2D (one-out-of-two with diagnostics) voting architecture to block prompt injection, jailbreaks, malicious payloads, and PII/secret leakage.

**Status:** Experimental — under active development. Not certified for production use. Borrows architectural ideas from functional safety engineering (IEC 61508 patterns) but makes no certification or compliance claims.

## Core Concepts

- **Ingress evaluation**: Classifies user prompts as Pass or Block before they reach an LLM
- **Egress evaluation**: Scans LLM responses for PII leakage, secrets, and framing attacks
- **1oo2D voter**: Both Channel A and Channel B must agree on Pass; either can independently block (fail-closed)
- **Audit chain**: Every verdict produces a tamper-evident HMAC-chained audit entry
- **Profiles**: Multi-tenant intent allowlists restrict permitted prompt categories at init time

## Channel Architecture

| Channel | Type | Mechanism |
|---------|------|-----------|
| A | Ingress | FSM + allowlist regex (intent patterns) |
| B | Ingress | Deterministic rule engine (structural/lexical) |
| C | Advisory | Non-safety heuristic opinions (logged, not blocking) |
| D | Ingress (optional) | Semantic embeddings via ONNX Runtime (`semantic` feature) |
| E | Egress | FSM-based PII/leakage sliding-window detection |
| F | Egress | Rule-based entropy/framing detection |

## Safety Properties

- `#![forbid(unsafe_code)]` on the entire `firewall-core` crate
- 50 ms watchdog deadline on all FSM evaluations (500 ms in debug builds)
- Hard reject inputs > 8192 bytes (no silent truncation)
- Fail-closed: any fault, uninitialised state, or channel disagreement → Block
- Init guard: `OnceLock` prevents re-initialisation; production requires `POLICY_GATE_INIT_TOKEN`

## Verdict Kinds

| Kind | isPass | Meaning |
|------|--------|---------|
| `Pass` | ✓ | Both channels agree on same intent |
| `DiagnosticAgreement` | ✓ | Both pass, different intent — review within 72h |
| `Block` | ✗ | At least one channel blocked |
| `DiagnosticDisagreement` | ✗ | Channels disagree — review within 24h |

## Profiles

Profiles restrict permitted intents at `init()` time for multi-tenant deployments:

| Profile | Permitted Intents |
|---------|-------------------|
| `Default` | All built-in intents (IP-001…IP-099) including AgenticToolUse |
| `CodeAssistant` | Factual, Causal, Comparative, CodeGeneration, Summarisation, Greeting, Ack, Meta |
| `CustomerService` | Factual, Comparative, Summarisation, Translation, Greeting, Ack, Meta |
| `Custom` | User-defined via `firewall.toml` |

## Best Fit

Good fit: narrow agent workflows with tool use, tenant-specific prompt policies, output validation for leakage/PII, multi-turn escalation detection.

Weaker fit: broad open-ended chatbot moderation, large unconstrained intent spaces.

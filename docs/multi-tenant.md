# Multi-Tenant Policy Hub (Pillar 5)

Each tenant gets a fully isolated security profile: its own `forbidden_keywords`, `permitted_intents`, `context_window`, and audit log. Requests are blocked by default if the `tenant_id` is unknown.

## Directory-based registry

Each `.toml` file in a directory defines one tenant. The filename (minus `.toml`) is used as the `tenant_id` unless overridden inside the file.

```bash
# Load all tenant configs at startup
policy_gate.init_multi_tenant_registry(
    token="your-secret-token",
    dir_path="/etc/policy-gate/tenants/"
)
```

```rust
// Rust
policy_gate::init_multi_tenant_registry(
    "your-secret-init-token",
    "/etc/policy-gate/tenants/"
).expect("Failed to load tenant registry");
```

## Evaluating with tenant context

```typescript
const verdict = await firewall.evaluateForTenant(
  "customer-123",
  "What is the capital of France?"
);
```

```python
verdict = policy_gate.evaluate_raw_for_tenant(
    raw="What is the capital of France?",
    sequence=123,
    tenant_id="customer-a"
)
```

## Voter strictness per tenant

By default, `DiagnosticAgreement` (both channels pass but disagree on intent) is allowed through and queued for 72h review. For high-sensitivity tenants, escalate to a hard Block:

```toml
# policy-hub/tenants/finance-prod.toml
tenant_id = "finance-prod"
allow_anonymous_tenants = false
on_diagnostic_agreement = "fail_closed"
audit_detail_level = "detailed"
semantic_enforce_threshold = 0.85
```

| Value | Behaviour | Use when |
|---|---|---|
| `pass_and_log` | Allow, queue for review (default) | General tenants |
| `fail_closed` | Escalate to Block | Finance, PII, healthcare |

## Pre-built profiles (Policy Hub)

| Profile | Path | Purpose |
|---|---|---|
| Research Agent | `policy-hub/profiles/research-agent/firewall.toml` | Extended egress controls |
| Code Assistant | `policy-hub/profiles/code-assistant/firewall.toml` | Code-specific rules |
| Customer Support | `policy-hub/profiles/customer-support/firewall.toml` | PII protection |
| Strict preset | `policy-hub/presets/strict.toml` | Maximum restriction |
| Permissive preset | `policy-hub/presets/permissive.toml` | Minimal restriction |

See [`policy-hub/README.md`](../policy-hub/README.md) for full documentation.

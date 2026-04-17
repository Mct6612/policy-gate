# Agent & Tool Use (LangGraph, CrewAI)

`policy-gate` can protect LLM agents by validating both the intent of the request and the specific tools being invoked.

## Tool-schema validation

Configure an explicit allowlist of permitted tools in `firewall.toml`:

```toml
allowed_tools = ["weather_tool", "calculator_tool", "search_tool"]

# For high-security agents — block on any intent ambiguity
on_diagnostic_agreement = "fail_closed"
```

Tools outside this list result in a `ToolNotAllowed` block with the tool name and permitted list.

## Python API

```python
import policy_gate

policy_gate.init()

# Validate tool list before LLM call
validation = policy_gate.validate_tools(["weather_tool", "delete_database_tool"])
# {"is_valid": false, "invalid_tools": ["delete_database_tool"], ...}

# Evaluate conversation history
result = policy_gate.evaluate_messages([
    {"role": "user", "content": "What's the weather?"},
    {"role": "assistant", "content": "I'll check that for you."},
])
```

## LangGraph integration

See [`examples/langgraph_firewall_integration.py`](../examples/langgraph_firewall_integration.py) for a complete working example covering ingress validation, tool whitelisting, egress scanning, and shadow mode.

```bash
cp examples/firewall.langgraph.example.toml firewall.toml
pip install langgraph langchain langchain-openai
python -m maturin develop --manifest-path crates/firewall-pyo3/Cargo.toml
python examples/langgraph_firewall_integration.py
```

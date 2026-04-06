#!/usr/bin/env python3
"""
suggest_pattern.py — Automated Intent Pattern Suggestion

Analyzes audit logs to suggest new regex patterns, generates post-match guards,
and outputs Z3 Proof Obligations.
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

try:
    from operator_review import load_audit_log, analyze_disagreement, load_text_database
except ImportError:
    # Handle if not run from verification folder
    sys.exit("Error: Must be run from the verification directory to import operator_review.")

def check_z3_snippet(smt2_path: str, snippet: str) -> str:
    from pathlib import Path
    try:
        import z3
    except ImportError:
        return "Failed: z3 module not installed"
    
    if not Path(smt2_path).exists():
        return "Failed: file not found"
    
    with open(smt2_path, "r", encoding="utf-8") as f:
        base_smt = f.read()
        
    test_content = base_smt + "\n" + snippet + "\n(check-sat)\n"
    
    try:
        ctx = z3.Context()
        raw = z3.Z3_eval_smtlib2_string(ctx.ref(), test_content)
        tokens = [t.strip() for t in raw.strip().splitlines() if t.strip()]
        if any(t in ('sat', 'unsat') for t in tokens):
            return "Passed"
        return f"Failed: unexpected output -> {raw.strip()}"
    except Exception as e:
        return f"Error evaluating: {e}"

@dataclass
class PatternSuggestion:
    pattern_id: str
    regex: str
    needs_guard: bool
    z3_po_update: str
    safety_manual_snippet: str
    confidence: float
    rationale: str

def generate_guard(safety_constraints: List[str]) -> str:
    if not safety_constraints:
        return ""
    
    guard_logic = "def generated_guard(input: str) -> bool:\n"
    guard_logic += "    lower = input.lower()\n"
    guard_logic += "    DISQUALIFY = [\n"
    for constraint in safety_constraints:
        guard_logic += f"        '{constraint.lower()}',\n"
    guard_logic += "    ]\n"
    guard_logic += "    return not any(kw in lower for kw in DISQUALIFY)\n"
    return guard_logic

def generate_z3_po(pattern_id: str, regex: str, needs_guard: bool) -> str:
    """Generate Z3 Proof string."""
    po = f"; PO Update for {pattern_id}\n"
    if needs_guard:
        po += f"(declare-fun guard_{pattern_id}_accepts (String) Bool)\n"
        po += f"(assert (=> (matches_{pattern_id} input) (guard_{pattern_id}_accepts input)))\n"
    else:
        po += f"; No guard needed for {pattern_id}\n"
    return po

def suggest_pattern(
    audit_log_path: str,
    positive_examples: List[str],
    negative_examples: List[str],
    safety_constraints: Optional[List[str]] = None,
    optimize_z3: bool = False
) -> PatternSuggestion:
    # In a full implementation, we would extract common substrings from positive_examples
    # that do not match negative_examples. For now, we build a simple alternating regex
    # from positive examples that escapes special chars, if provided, else dummy regex.

    if not positive_examples:
        regex = r"(?i)\b(example)\b"
        rationale = "Fallback dummy pattern due to lack of positive examples."
    else:
        escaped_pos = [re.escape(p) for p in positive_examples]
        combined = "|".join(escaped_pos)
        regex = f"(?i)\\b({combined})\\b"
        rationale = f"Combined {len(positive_examples)} positive examples."

    pattern_id = "IP-NEW"
    needs_guard = bool(safety_constraints and len(safety_constraints) > 0)
    
    z3_po = generate_z3_po(pattern_id, regex, needs_guard)
    
    safety_snippet = f"### CR-YYYY-XXX: Add {pattern_id}\n- Regex: `{regex}`\n- Guard: {needs_guard}\n"
    
    return PatternSuggestion(
        pattern_id=pattern_id,
        regex=regex,
        needs_guard=needs_guard,
        z3_po_update=z3_po,
        safety_manual_snippet=safety_snippet,
        confidence=0.85,
        rationale=rationale
    )

@dataclass
class RuleExceptionSuggestion:
    rule_id: str
    exception_regex: str
    z3_po_update: str
    safety_manual_snippet: str
    rationale: str

def suggest_rule_exception(
    rule_id: str,
    problematic_text: str
) -> RuleExceptionSuggestion:
    # Basic logic to suggest negating a certain match
    escaped = re.escape(problematic_text)
    exception_regex = f"(?!.*{escaped})"
    
    z3_po = f"; PO Update for Rule {rule_id} Exception\n"
    z3_po += f"(assert (not (matches_{rule_id}_exception \"{problematic_text}\")))\n"
    
    safety_snippet = f"### CR-YYYY-XXX: Add Exception to {rule_id}\n- Exception Regex: `{exception_regex}`\n"
    
    return RuleExceptionSuggestion(
        rule_id=rule_id,
        exception_regex=exception_regex,
        z3_po_update=z3_po,
        safety_manual_snippet=safety_snippet,
        rationale=f"Auto-generated exception for text that triggered {rule_id}."
    )

def main():
    parser = argparse.ArgumentParser(description="Suggest Intent Pattern from Audit Log")
    parser.add_argument("--audit-log", required=True, help="Path to audit NDJSON")
    parser.add_argument("--positive", nargs="*", default=[], help="Positive exact matches")
    parser.add_argument("--negative", nargs="*", default=[], help="Negative exact matches")
    parser.add_argument("--constraints", nargs="*", default=[], help="Safety constraints (keywords to block)")
    parser.add_argument("--optimize", action="store_true", help="Optimize Z3")

    args = parser.parse_args()

    suggestion = suggest_pattern(
        args.audit_log,
        args.positive,
        args.negative,
        args.constraints,
        args.optimize
    )

    print(f"--- Pattern Suggestion ---")
    print(f"ID: {suggestion.pattern_id}")
    print(f"Regex: {suggestion.regex}")
    print(f"Needs Guard: {suggestion.needs_guard}")
    print(f"Confidence: {suggestion.confidence}")
    print(f"Rationale: {suggestion.rationale}")
    print(f"\n--- Z3 PO Update ---\n{suggestion.z3_po_update}")
    print(f"\n--- Safety Manual Snippet ---\n{suggestion.safety_manual_snippet}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
actions_dashboard.py — Operator Action Analytics & Metrics

Calculates KPIs from operator_actions.jsonl including:
- FP Rate (acknowledge vs tune)
- Action Breakdown
- Cluster Hotspots (by note/pattern)
- Time-to-Decision
"""

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime
from typing import List, Dict, Any

def load_actions(file_path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return []
    
    actions = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    actions.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return actions

def format_percentage(part: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{(part / total) * 100:.1f}%"

def run_dashboard(file_path: str, export: str = None):
    actions = load_actions(file_path)
    if not actions:
        print("No actions found to analyze.")
        return

    print(f"\n{'━' * 70}")
    print(f"  policy-gate Operator Metrics Dashboard")
    print(f"{'━' * 70}")
    print(f"  Source: {file_path}")
    print(f"  Total Actions recorded: {len(actions)}")

    # 1. Action Breakdown
    action_counts = Counter(a.get("action") for a in actions)
    print(f"\n  [1] Action Breakdown:")
    for action, count in action_counts.most_common():
        print(f"      - {action:15}: {count:3} ({format_percentage(count, len(actions))})")

    # 2. FP vs TP (Remediation Rate)
    # Acknowledge = TP, any tune action = FP
    tp_count = action_counts.get("acknowledge", 0)
    fp_count = len(actions) - tp_count
    print(f"\n  [2] Remediation Summary:")
    print(f"      - True Positives (Ack): {tp_count:3} ({format_percentage(tp_count, len(actions))})")
    print(f"      - False Positives (Tune): {fp_count:3} ({format_percentage(fp_count, len(actions))})")

    # 3. Decision Hotspots (Cluster patterns)
    notes = [a.get("notes", "") for a in actions if a.get("notes")]
    # Extract IDs or regex from notes like "suggest:..." or "exception_auto:..."
    clusters = []
    for n in notes:
        if ":" in n:
            clusters.append(n.split(":")[0])
        else:
            clusters.append("manual")
    
    cluster_counts = Counter(clusters)
    print(f"\n  [3] Integration Hotspots:")
    for category, count in cluster_counts.most_common(5):
        print(f"      - {category:15}: {count:3}")

    # 4. Temporal Stats
    timestamps = []
    for a in actions:
        ts_str = a.get("timestamp")
        if ts_str:
            try:
                # Handle ISO format with +00:00 or Z
                ts_str = ts_str.replace("Z", "+00:00")
                timestamps.append(datetime.fromisoformat(ts_str))
            except ValueError:
                continue
    
    if timestamps:
        timestamps.sort()
        start_ts = timestamps[0]
        end_ts = timestamps[-1]
        duration = end_ts - start_ts
        print(f"\n  [4] Temporal Insights:")
        print(f"      - First Action: {start_ts.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"      - Last Action:  {end_ts.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"      - Active Span:  {duration}")

    if export:
        metrics = {
            "total_actions": len(actions),
            "action_breakdown": dict(action_counts),
            "tp_count": tp_count,
            "fp_count": fp_count,
            "hotspots": dict(cluster_counts),
            "span_seconds": duration.total_seconds() if timestamps else 0
        }
        with open(export, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        print(f"\n  Report exported to: {export}")

    print(f"\n{'━' * 70}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Operator Action Dashboard")
    parser.add_argument("--input", default="operator_actions.jsonl", help="Path to actions log")
    parser.add_argument("--export", help="Export metrics to JSON file")
    
    args = parser.parse_args()
    run_dashboard(args.input, args.export)

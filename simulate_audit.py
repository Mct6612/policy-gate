import hashlib
import json
import os
import time

AUDIT_FILE = "simulated_audit.ndjson"

_sequence_counter = 0


def next_sequence():
    global _sequence_counter
    _sequence_counter += 1
    return _sequence_counter


def append_record(verdict):
    record = {
        "schema_version": 1,
        "sequence": next_sequence(),
        "verdict_kind": verdict,
        "input_hash": hashlib.sha256(verdict.encode()).hexdigest(),
        "total_elapsed_us": 100,
        "decided_at_ns": int(time.time() * 1_000_000_000),
    }
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")


try:
    os.remove(AUDIT_FILE)
except FileNotFoundError:
    pass

print(f"Simulating audit trail in {AUDIT_FILE}...")

# 1. Add 10 Pass records
for _ in range(10):
    append_record("Pass")
    time.sleep(0.1)

# 2. Add 10 DiagnosticDisagreement records (should trigger >5% alert)
for _ in range(10):
    append_record("DiagnosticDisagreement")
    time.sleep(0.1)

# 3. Add a DiagnosticDisagreement
append_record("DiagnosticDisagreement")

print("Simulation finished.")

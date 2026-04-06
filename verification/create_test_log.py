import json
import time
import os

log_file = "verification/test_log.jsonb"
text_db_file = "verification/test_text.db"

disagreement = {
    "verdict_kind": "DiagnosticDisagreement",
    "sequence": 1,
    "decided_at_ns": int(time.time() * 1e9),
    "input_hash": "hash123",
    "schema_version": 2,
    "channel_a_result": {
        "decision": {
            "type": "Pass",
            "intent": "TaskCodeGeneration",
            "pattern_id": "IP-020"
        }
    },
    "channel_b_result": {
        "decision": {
            "type": "Block",
            "reason": "Forbidden Pattern: 'print(sys.argv)'",
            "pattern_id": "RE-004"
        }
    }
}

with open(log_file, "w") as f:
    for i in range(1, 4):
        d = disagreement.copy()
        d["sequence"] = i
        f.write(json.dumps(d) + "\n")

with open(text_db_file, "w") as f:
    f.write("hash123\tWrite a python script that does print(sys.argv)\tWrite a python script that does print(sys.argv)\n")

print("Created test logs.")

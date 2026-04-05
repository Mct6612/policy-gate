// crates/firewall-core/src/semantic_generated.rs
//
// Auto-generated semantic centroids from AdvBench + JailbreakBench
// Generated via: python scripts/generate_centroids.py
//
// 8 attack centroids, 384 dimensions (MiniLM embedding space)
// Hash tripwire: EXPECTED_CENTROID_HASH must match actual centroid hash in CI

pub const CENTROID_DIMENSIONS: usize = 384;

/// Expected SHA256 hash of centroids (tripwire for CI)
pub const EXPECTED_CENTROID_HASH: &str = "placeholder_hash_update_via_generate_centroids";

/// 8 learned attack centroids from AdvBench + JailbreakBench
/// Format: (category_name, 384-dimensional embedding)
pub const ATTACK_CENTROIDS: &[(&str, &[f32; CENTROID_DIMENSIONS])] = &[
    ("jailbreak_roleplay", &CENTROID_JAILBREAK_ROLEPLAY),
    ("jailbreak_hypothetical", &CENTROID_JAILBREAK_HYPOTHETICAL),
    ("injection_system_prompt", &CENTROID_INJECTION_SYSTEM),
    ("injection_ignore_instructions", &CENTROID_INJECTION_IGNORE),
    ("malware_code_generation", &CENTROID_MALWARE_CODE),
    ("credential_extraction", &CENTROID_CREDENTIAL_EXTRACT),
    ("privilege_escalation", &CENTROID_PRIV_ESCALATION),
    ("data_exfiltration", &CENTROID_DATA_EXFIL),
];

// Placeholder centroids (384 dimensions each)
// In production, these are generated from actual embeddings via generate_centroids.py

#[allow(dead_code)]
const CENTROID_JAILBREAK_ROLEPLAY: [f32; CENTROID_DIMENSIONS] = [0.0; CENTROID_DIMENSIONS];

#[allow(dead_code)]
const CENTROID_JAILBREAK_HYPOTHETICAL: [f32; CENTROID_DIMENSIONS] = [0.0; CENTROID_DIMENSIONS];

#[allow(dead_code)]
const CENTROID_INJECTION_SYSTEM: [f32; CENTROID_DIMENSIONS] = [0.0; CENTROID_DIMENSIONS];

#[allow(dead_code)]
const CENTROID_INJECTION_IGNORE: [f32; CENTROID_DIMENSIONS] = [0.0; CENTROID_DIMENSIONS];

#[allow(dead_code)]
const CENTROID_MALWARE_CODE: [f32; CENTROID_DIMENSIONS] = [0.0; CENTROID_DIMENSIONS];

#[allow(dead_code)]
const CENTROID_CREDENTIAL_EXTRACT: [f32; CENTROID_DIMENSIONS] = [0.0; CENTROID_DIMENSIONS];

#[allow(dead_code)]
const CENTROID_PRIV_ESCALATION: [f32; CENTROID_DIMENSIONS] = [0.0; CENTROID_DIMENSIONS];

#[allow(dead_code)]
const CENTROID_DATA_EXFIL: [f32; CENTROID_DIMENSIONS] = [0.0; CENTROID_DIMENSIONS];

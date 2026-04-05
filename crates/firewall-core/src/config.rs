// crates/firewall-core/src/config.rs — Pluggable Configuration Loading
//
// Safety Action SA-048: Load custom intent patterns and forbidden keywords
// from an optional firewall.toml file at startup.
//
// This module is only active during the init() phase.

use crate::types::{AuditDetailLevel, MatchedIntent};
use serde::Deserialize;


/// Configuration structure for the firewall.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct FirewallConfig {
    /// Optional tenant ID for diagnostic traceability.
    pub tenant_id: Option<String>,
    /// Optional list of custom intent patterns.
    pub intents: Option<Vec<IntentEntry>>,
    /// Optional list of additional forbidden keywords.
    pub forbidden_keywords: Option<Vec<String>>,
    /// Lookback window for contextual evaluation (Red-Team Strategy 3).
    /// Default is 3 if not specified.
    pub context_window: Option<usize>,
    /// Shadow Mode: evaluates inputs but allows them to pass even if blocked.
    pub shadow_mode: Option<bool>,
    #[cfg(feature = "semantic")]
    pub semantic_model_path: Option<String>,
    /// Optional path to the tokenizer for Channel D.
    #[cfg(feature = "semantic")]
    pub tokenizer_path: Option<String>,
    /// SA-XXX: Audit detail level for operator review support.
    /// "basic" (default) stores only block_reason and hash.
    /// "detailed" stores full ChannelResult for side-by-side analysis.
    /// Increases audit log size but enables operator_review.py to analyze
    /// DiagnosticDisagreement events with full channel details.
    #[serde(default)]
    pub audit_detail_level: Option<AuditDetailLevel>,
    /// Semantic tagging threshold (0.0 to 1.0). Default: 0.70.
    pub semantic_threshold: Option<f32>,
    /// Semantic enforcement (blocking) threshold (0.0 to 1.0). Default: 1.0 (disabled).
    pub semantic_enforce_threshold: Option<f32>,
    /// If false (default), requests without a valid tenant ID are rejected.
    #[serde(default)]
    pub allow_anonymous_tenants: Option<bool>,
    /// Optional list of permitted intents for this configuration (multi-tenant profile).
    pub permitted_intents: Option<Vec<MatchedIntent>>,
}

/// A single intent pattern entry in the configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct IntentEntry {
    /// Stable ID for traceability (e.g., IP-200).
    pub id: String,
    /// Intent class (must match MatchedIntent variants).
    pub intent: MatchedIntent,
    /// Regular expression pattern.
    pub regex: String,
}

impl FirewallConfig {
    /// Validates the configuration without applying it.
    /// Checks for regex syntax errors and ensures the set of patterns is compatible.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // 1. Check individual regexes and duplicate IDs
        if let Some(intents) = &self.intents {
            let mut ids = std::collections::HashSet::new();
            let mut regex_sources = Vec::new();

            for entry in intents {
                if !ids.insert(&entry.id) {
                    errors.push(format!("Duplicate intent ID: {}", entry.id));
                }
                match regex::Regex::new(&entry.regex) {
                    Ok(_) => regex_sources.push(entry.regex.as_str()),
                    Err(e) => errors.push(format!("Invalid regex in [{}]: {}", entry.id, e)),
                }
            }

            // 2. Check global RegexSet compatibility (catch overlap/recursion/complexity issues)
            if errors.is_empty() {
                if let Err(e) = regex::RegexSet::new(regex_sources) {
                    errors.push(format!("RegexSet compilation failed: {}", e));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Loads the configuration from the default location (firewall.toml).
    pub fn load() -> Result<Self, String> {
        self::FirewallConfig::load_from_path("firewall.toml")
    }

    /// Loads the configuration from an arbitrary path.
    pub fn load_from_path<P: AsRef<std::path::Path>>(path: P) -> Result<Self, String> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = path;
            Ok(FirewallConfig::default())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = path.as_ref();
            if !path.exists() {
                return Ok(FirewallConfig::default());
            }

            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;

            Self::from_toml_str(&content)
        }
    }

    /// Loads configuration from a TOML string.
    pub fn from_toml_str(content: &str) -> Result<Self, String> {
        toml::from_str(content).map_err(|e| format!("Failed to parse TOML configuration: {e}"))
    }

    /// Loads configuration from a JSON string.
    pub fn from_json_str(content: &str) -> Result<Self, String> {
        serde_json::from_str(content).map_err(|e| format!("Failed to parse JSON configuration: {e}"))
    }
}

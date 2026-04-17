// crates/firewall-core/src/config.rs — Pluggable Configuration Loading
//
// Safety Action SA-048: Load custom intent patterns and forbidden keywords
// from an optional firewall.toml file at startup.
//
// This module is only active during the init() phase.

use crate::types::{AuditDetailLevel, MatchedIntent};
use serde::Deserialize;

/// Controls voter behaviour when both channels agree on Pass but disagree on
/// the matched intent (DiagnosticAgreement).
///
/// **`PassAndLog`** (default): the request is allowed through and the event is
/// queued for operator review (SR-008: review within 72 h). Suitable for most
/// tenants.
///
/// **`FailClosed`**: the DiagnosticAgreement is escalated to a hard Block.
/// Recommended for high-sensitivity tenants (e.g. financial data, PII-heavy
/// workflows) where any intent ambiguity is unacceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnDiagnosticAgreement {
    /// Allow the request through and log for review. (default)
    #[default]
    PassAndLog,
    /// Treat intent disagreement as a Block (fail-closed hardening).
    FailClosed,
}

// SA-084: ReDoS protection - regex complexity limits
const MAX_PATTERN_LENGTH: usize = 1024;
const MAX_QUANTIFIER_DEPTH: usize = 3;
const MAX_ALTERNATION_COUNT: usize = 10;
const MAX_STAR_PLUS_NESTING: usize = 2;

/// Configuration structure for the firewall.
impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            tenant_id: None,
            #[cfg(feature = "semantic")]
            engine_mode: Some("fast".to_string()),
            #[cfg(feature = "semantic")]
            model_path: None,
            #[cfg(feature = "semantic")]
            tokenizer_path: None,
            intents: None,
            forbidden_keywords: None,
            context_window: Some(3),
            shadow_mode: None,
            audit_detail_level: Some(AuditDetailLevel::Basic),
            semantic_threshold: Some(0.70),
            semantic_enforce_threshold: Some(1.0),
            allow_anonymous_tenants: Some(true),
            permitted_intents: None,
            rule_exceptions: None,
            on_diagnostic_agreement: OnDiagnosticAgreement::PassAndLog,
            streaming_egress_enabled: false,
            streaming_egress_final_check: true,
            allowed_tools: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct FirewallConfig {
    /// Optional tenant ID for diagnostic traceability.
    pub tenant_id: Option<String>,
    /// SA-050: Semantic engine mode: "fast" (default) or "bert".
    #[cfg(feature = "semantic")]
    pub engine_mode: Option<String>,
    #[cfg(feature = "semantic")]
    pub model_path: Option<String>,
    /// Optional path to the tokenizer for Channel D.
    #[cfg(feature = "semantic")]
    pub tokenizer_path: Option<String>,
    /// Optional list of custom intent patterns.
    pub intents: Option<Vec<IntentEntry>>,
    /// Optional list of additional forbidden keywords.
    pub forbidden_keywords: Option<Vec<String>>,
    /// Lookback window for contextual evaluation (Red-Team Strategy 3).
    /// Default is 3 if not specified.
    pub context_window: Option<usize>,
    /// Shadow Mode: evaluates inputs but allows them to pass even if blocked.
    pub shadow_mode: Option<bool>,
    /// Audit detail level for operator review support.
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
    /// Optional list of rule exceptions (SA-XXX).
    pub rule_exceptions: Option<Vec<RuleExceptionEntry>>,
    /// Voter policy when both channels agree on Pass but disagree on intent.
    /// `pass_and_log` (default) allows the request through and queues a review.
    /// `fail_closed` escalates the DiagnosticAgreement to a hard Block.
    /// Recommended value for high-sensitivity tenants: `fail_closed`.
    #[serde(default)]
    pub on_diagnostic_agreement: OnDiagnosticAgreement,

    // ── Pillar 6: Streaming Egress ──────────────────────────────────────────
    /// Enable streaming egress scanning via Aho-Corasick (Pillar 6 — experimental).
    ///
    /// Requires proxy compiled with `--features streaming-egress`.
    /// When `false` (default), the proxy rejects `stream: true` requests with HTTP 400.
    /// When `true`, streaming responses are scanned chunk-by-chunk with a 256-byte
    /// overlap buffer to guarantee cross-boundary detection.
    #[serde(default)]
    pub streaming_egress_enabled: bool,

    /// Run a full `evaluate_output()` over the complete accumulated text when `[DONE]`
    /// is received. Adds ~1–3 ms at stream end and emits a divergence counter if the
    /// final check disagrees with the streaming scan (should never happen by design).
    ///
    /// Set to `false` for latency-sensitive deployments that trust the AC scan fully.
    /// Default: `true`.
    #[serde(default = "default_streaming_egress_final_check")]
    pub streaming_egress_final_check: bool,

    // ── Tool-Schema Validation (AgenticToolUse Enhancement) ──────────────────
    /// Optional whitelist of allowed tool names for AgenticToolUse validation.
    /// When specified, only these tools may be invoked. Tool calls to other tools
    /// result in a Block with reason `ToolNotAllowed`.
    ///
    /// Example: `["weather_tool", "calculator_tool"]`
    /// If `None` or empty, all tools are permitted (backward compatible).
    #[serde(default)]
    pub allowed_tools: Option<Vec<String>>,
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

/// A single rule exception entry in the configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct RuleExceptionEntry {
    /// The rule ID this exception applies to (e.g., RE-004).
    pub rule_id: String,
    /// Regular expression pattern; if it matches, the rule block is ignored.
    pub regex: String,
    /// Reason for the exception for audit transparency.
    pub reason: String,
}

/// SA-084: Validate regex pattern for ReDoS vulnerabilities
/// Returns Ok(()) if pattern is safe, Err(reason) if potentially dangerous
fn default_streaming_egress_final_check() -> bool {
    true
}

fn validate_regex_redos(pattern: &str) -> Result<(), String> {
    // 1. Length check - extremely long patterns are suspicious
    if pattern.len() > MAX_PATTERN_LENGTH {
        return Err(format!(
            "Pattern exceeds maximum length of {} characters (ReDoS protection)",
            MAX_PATTERN_LENGTH
        ));
    }

    // 2. Parse with regex-syntax to analyze AST complexity
    // This catches syntactically invalid patterns and measures complexity
    use regex_syntax::Parser;

    let mut parser = Parser::new();
    match parser.parse(pattern) {
        Ok(ast) => {
            // Check AST nesting depth by counting group nodes
            let ast_str = format!("{:?}", ast);
            let group_depth = ast_str.matches("Group(").count();
            if group_depth > 10 {
                return Err(format!(
                    "Pattern AST nesting depth {} exceeds limit of 10 (ReDoS protection)",
                    group_depth
                ));
            }
        }
        Err(e) => {
            return Err(format!(
                "Regex syntax error (potential ReDoS risk): {}. Pattern rejected.",
                e
            ));
        }
    }

    // 3. Heuristic: check for dangerous nested quantifiers
    // Patterns like (a+)+, (a*)*, ((a+)?)+ are classic ReDoS vectors
    let star_plus_count = pattern.matches('+').count() + pattern.matches('*').count();
    let paren_depth = pattern.chars().filter(|&c| c == '(' || c == ')').count() / 2;

    if star_plus_count > MAX_QUANTIFIER_DEPTH && paren_depth > MAX_STAR_PLUS_NESTING {
        // Check if quantifiers are nested (heuristic: quantifier followed by paren)
        let nested_pattern = pattern.contains("+(")
            || pattern.contains("*(")
            || pattern.contains("+[")
            || pattern.contains("*[");

        if nested_pattern {
            return Err(format!(
                "Pattern contains potentially dangerous nested quantifiers (ReDoS risk: {} quantifiers, {} nesting)",
                star_plus_count, paren_depth
            ));
        }
    }

    // 4. Check for excessive alternation (|) which can cause exponential blowup
    let alternation_count = pattern.matches('|').count();
    if alternation_count > MAX_ALTERNATION_COUNT {
        return Err(format!(
            "Pattern contains {} alternations, exceeding limit of {} (ReDoS protection)",
            alternation_count, MAX_ALTERNATION_COUNT
        ));
    }

    // 5. Check for catastrophic backtracking patterns like (a+)+ or (a*)*
    // Count dangerous quantifier patterns
    let dangerous_count = [".*", ".+", ".?", "+", "*"]
        .iter()
        .filter(|&&p| pattern.contains(p))
        .count();

    if dangerous_count >= 3 && paren_depth >= 2 {
        return Err(format!(
            "Pattern contains multiple dangerous quantifiers (ReDoS protection: {} dangerous patterns, {} depth)",
            dangerous_count, paren_depth
        ));
    }

    Ok(())
}

impl FirewallConfig {
    /// Validates the configuration without applying it.
    /// Checks for regex syntax errors and ensures the set of patterns is compatible.
    /// SA-084: Also validates for ReDoS vulnerabilities.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // 1. Check individual regexes, duplicate IDs, and ReDoS safety
        if let Some(intents) = &self.intents {
            let mut ids = std::collections::HashSet::new();
            let mut regex_sources = Vec::new();

            for entry in intents {
                if !ids.insert(&entry.id) {
                    errors.push(format!("Duplicate intent ID: {}", entry.id));
                }

                // SA-084: ReDoS validation before regex compilation
                if let Err(e) = validate_regex_redos(&entry.regex) {
                    errors.push(format!("ReDoS validation failed for [{}]: {}", entry.id, e));
                    continue;
                }

                match regex::Regex::new(&entry.regex) {
                    Ok(_) => regex_sources.push(entry.regex.as_str()),
                    Err(e) => errors.push(format!("Invalid regex in [{}]: {}", entry.id, e)),
                }
            }

            // 2. Check global RegexSet compatibility (catch overlap/recursion/complexity issues)
            if errors.is_empty() && !regex_sources.is_empty() {
                if let Err(e) = regex::RegexSet::new(regex_sources) {
                    errors.push(format!("RegexSet compilation failed: {}", e));
                }
            }
        }

        // 3. Check rule exceptions regexes with ReDoS validation
        if let Some(exceptions) = &self.rule_exceptions {
            for entry in exceptions {
                // SA-084: ReDoS validation for exception patterns too
                if let Err(e) = validate_regex_redos(&entry.regex) {
                    errors.push(format!(
                        "ReDoS validation failed for exception [{}]: {}",
                        entry.rule_id, e
                    ));
                    continue;
                }

                if let Err(e) = regex::Regex::new(&entry.regex) {
                    errors.push(format!(
                        "Invalid regex in exception for [{}]: {}",
                        entry.rule_id, e
                    ));
                }
            }
        }

        // 4. Streaming egress: reject if enabled and any built-in pattern anchor exceeds
        //    STREAM_EGRESS_MAX_PATTERN_BYTES. This ensures cross-boundary detection is
        //    guaranteed by the 256-byte overlap buffer.
        #[cfg(feature = "streaming-egress")]
        if self.streaming_egress_enabled {
            use crate::stream_scanner::{BUILTIN_PATTERNS, STREAM_EGRESS_MAX_PATTERN_BYTES};
            // BUILTIN_PATTERNS is pub(crate) — only reachable within firewall-core
            for (id, pattern) in BUILTIN_PATTERNS {
                if pattern.len() > STREAM_EGRESS_MAX_PATTERN_BYTES {
                    errors.push(format!(
                        "Streaming egress validation error for tenant \"{}\":\n  \
                         Pattern \"{}\" has an anchor length of {} bytes.\n  \
                         The streaming egress scanner uses a 256-byte overlap buffer.\n  \
                         Patterns with anchors longer than {} bytes cannot be reliably\n  \
                         detected across SSE chunk boundaries (the overlap covers at most\n  \
                         255 bytes, and a pattern of length L requires at least L-1 bytes\n  \
                         of overlap).\n  \
                         Options:\n    \
                         (a) Shorten the pattern anchor to \u{2264} {} bytes.\n    \
                         (b) Disable streaming egress for this tenant (streaming_egress_enabled = false).\n    \
                         (c) Increase STREAM_EGRESS_OVERLAP_BYTES in stream_scanner.rs and recompile\n        \
                             (not recommended without re-running the verification suite).",
                        self.tenant_id.as_deref().unwrap_or("(default)"),
                        id,
                        pattern.len(),
                        STREAM_EGRESS_MAX_PATTERN_BYTES,
                        STREAM_EGRESS_MAX_PATTERN_BYTES,
                    ));
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
        let path = "firewall.toml";
        if std::path::Path::new(path).exists() {
            println!("CONFIG: Loading from {}", path);
            Self::load_from_path(path)
        } else {
            println!("CONFIG: No firewall.toml found, using defaults");
            Ok(Self::default())
        }
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
        serde_json::from_str(content)
            .map_err(|e| format!("Failed to parse JSON configuration: {e}"))
    }
}

// ─── Global Config Storage ────────────────────────────────────────────────────
// SA-048: Global configuration storage for runtime access (e.g., from bindings).
// This is set during init() and can be updated during hot-reloads.

use std::sync::OnceLock;

static CURRENT_CONFIG: OnceLock<FirewallConfig> = OnceLock::new();

/// Sets the global configuration. Called during init() and hot-reloads.
/// Returns Err if the config was already set (should not happen in normal operation).
pub fn set_global_config(config: FirewallConfig) -> Result<(), Box<FirewallConfig>> {
    CURRENT_CONFIG.set(config).map_err(Box::new)
}

/// Gets the current global configuration, if one has been set.
/// Returns None if init() has not been called yet.
pub fn get_current_config() -> Option<&'static FirewallConfig> {
    CURRENT_CONFIG.get()
}

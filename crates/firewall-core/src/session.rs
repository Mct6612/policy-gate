// session.rs — SA-076: Session-Aware-Layer for Multi-Turn Conversation Memory
//
// Addresses the fundamental limitation of stateless design: inability to detect
// multi-turn escalation attacks and payload fragmentation across conversation turns.
//
// This layer maintains a sliding window of recent messages per session and provides
// cross-turn analytics while preserving the core firewall's stateless safety guarantees.

use crate::types::{BlockReason, ChannelDecision, MatchedIntent, PromptInput, VerdictKind};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Session context for multi-turn conversation memory.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: String,
    pub messages: VecDeque<SessionMessage>,
    pub created_at_ns: u128,
    pub last_activity_ns: u128,
    pub escalation_score: u8,
    pub fragmentation_detected: bool,
    pub topic_drift_detected: bool,
}

/// Individual message in session context.
#[derive(Debug, Clone)]
pub struct SessionMessage {
    pub sequence: u64,
    pub timestamp_ns: u128,
    pub input_text: String,
    pub input_hash: String,
    pub matched_intent: Option<MatchedIntent>,
    pub verdict: VerdictKind,
    pub block_reason: Option<BlockReason>,
    pub escalation_indicators: Vec<EscalationIndicator>,
}

/// Escalation indicators detected in message analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalationIndicator {
    /// Gradual increase in complexity or specificity
    ComplexityEscalation,
    /// Shift from general to sensitive topics
    TopicDrift,
    /// Attempt to bypass previous restrictions
    PolicyTesting,
    /// Repeated similar prompts with minor variations
    RepetitionWithVariation,
    /// Fragmented payload across multiple turns
    PayloadFragmentation,
}

/// Session manager for multi-turn conversation memory.
pub struct SessionManager {
    /// Session storage: session_id -> SessionContext
    sessions: Arc<Mutex<HashMap<String, SessionContext>>>,
    /// Maximum messages to keep per session (sliding window)
    max_messages: usize,
    /// Session timeout in nanoseconds
    session_timeout_ns: u128,
}

impl SessionManager {
    /// Create new session manager with default configuration.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            max_messages: 10, // Keep last 10 messages per session
            session_timeout_ns: Duration::from_secs(3600).as_nanos(), // 1 hour
        }
    }

    /// Create session manager with custom configuration.
    pub fn with_config(max_messages: usize, timeout_minutes: u64) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            max_messages,
            session_timeout_ns: Duration::from_secs(timeout_minutes * 60).as_nanos(),
        }
    }

    /// Add message to session context and analyze for escalation patterns.
    pub fn add_message(
        &self,
        session_id: &str,
        input: &PromptInput,
        verdict: VerdictKind,
        block_reason: Option<BlockReason>,
        matched_intent: Option<MatchedIntent>,
    ) -> SessionAnalysis {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();

        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());

        // Get or create session
        let session = sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionContext {
                session_id: session_id.to_string(),
                messages: VecDeque::new(),
                created_at_ns: now,
                last_activity_ns: now,
                escalation_score: 0,
                fragmentation_detected: false,
                topic_drift_detected: false,
            });

        // Update activity timestamp
        session.last_activity_ns = now;

        // Collect previous messages into a slice-compatible Vec before building the new message.
        // VecDeque does not coerce to &[T], so we snapshot here (max_messages is small, ≤10).
        let prev_msgs: Vec<SessionMessage> = session.messages.iter().cloned().collect();
        let escalation_indicators = self.analyze_message_indicators(&input.text, &prev_msgs);

        // Create session message
        let message = SessionMessage {
            sequence: session.messages.len() as u64 + 1,
            timestamp_ns: now,
            input_text: input.text.clone(),
            input_hash: crate::audit::sha256_hex(&input.text),
            matched_intent,
            verdict,
            block_reason,
            escalation_indicators,
        };

        // Add to session (maintain sliding window)
        session.messages.push_back(message.clone());
        if session.messages.len() > self.max_messages {
            session.messages.pop_front();
        }

        // Update escalation metrics
        self.update_session_metrics(session);

        // Generate analysis
        self.generate_analysis(session, &message)
    }

    /// Analyze individual message for escalation indicators.
    fn analyze_message_indicators(
        &self,
        text: &str,
        previous_messages: &[SessionMessage],
    ) -> Vec<EscalationIndicator> {
        let mut indicators = Vec::new();

        // Check for complexity escalation
        if self.is_complexity_escalation(text, previous_messages) {
            indicators.push(EscalationIndicator::ComplexityEscalation);
        }

        // Check for topic drift
        if self.is_topic_drift(text, previous_messages) {
            indicators.push(EscalationIndicator::TopicDrift);
        }

        // Check for policy testing
        if self.is_policy_testing(text, previous_messages) {
            indicators.push(EscalationIndicator::PolicyTesting);
        }

        // Check for repetition with variation
        if self.is_repetition_with_variation(text, previous_messages) {
            indicators.push(EscalationIndicator::RepetitionWithVariation);
        }

        // Check for payload fragmentation
        if self.is_payload_fragmentation(text, previous_messages) {
            indicators.push(EscalationIndicator::PayloadFragmentation);
        }

        indicators
    }

    /// Update session-level escalation metrics.
    fn update_session_metrics(&self, session: &mut SessionContext) {
        // Count escalation indicators in recent messages
        let recent_indicators: usize = session
            .messages
            .iter()
            .map(|msg| msg.escalation_indicators.len())
            .sum();

        // Calculate escalation score (0-255, capped at 100)
        session.escalation_score = (recent_indicators * 10).clamp(0, 100) as u8;

        // Detect fragmentation patterns
        session.fragmentation_detected = session.messages.iter().any(|msg| {
            msg.escalation_indicators
                .contains(&EscalationIndicator::PayloadFragmentation)
        });

        // Detect topic drift
        session.topic_drift_detected = session.messages.iter().any(|msg| {
            msg.escalation_indicators
                .contains(&EscalationIndicator::TopicDrift)
        });
    }

    /// Generate analysis
    fn generate_analysis(
        &self,
        session: &SessionContext,
        _current_message: &SessionMessage,
    ) -> SessionAnalysis {
        let mut flags = Vec::new();

        // High escalation score
        if session.escalation_score >= 70 {
            flags.push(SessionFlag::HighEscalationScore);
        }

        // Fragmentation detected
        if session.fragmentation_detected {
            flags.push(SessionFlag::FragmentationDetected);
        }

        // Topic drift detected
        if session.topic_drift_detected {
            flags.push(SessionFlag::TopicDriftDetected);
        }

        // Rapid escalation (score increased significantly in last 3 messages)
        if self.is_rapid_escalation(session) {
            flags.push(SessionFlag::RapidEscalation);
        }

        // Long session
        if session.messages.len() >= 8 {
            flags.push(SessionFlag::LongSession);
        }

        // Determine risk level based on flags and score
        let risk_level =
            if session.escalation_score >= 80 || flags.contains(&SessionFlag::RapidEscalation) {
                SessionRiskLevel::High
            } else if session.escalation_score >= 40
                || flags.contains(&SessionFlag::FragmentationDetected)
                || flags.contains(&SessionFlag::TopicDriftDetected)
            {
                SessionRiskLevel::Medium
            } else {
                SessionRiskLevel::Low
            };

        // Generate recommendations
        let recommendations = self.generate_recommendations(&risk_level, &flags);

        SessionAnalysis {
            session_id: session.session_id.clone(),
            risk_level,
            escalation_score: session.escalation_score,
            flags,
            message_count: session.messages.len(),
            session_duration_ns: session.last_activity_ns - session.created_at_ns,
            recommendations,
        }
    }

    /// Get current analysis for a session.
    pub fn get_analysis(&self, session_id: &str) -> Option<SessionAnalysis> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(session) = sessions.get(session_id) {
            if let Some(last_message) = session.messages.back() {
                return Some(self.generate_analysis(session, last_message));
            }
        }
        None
    }

    /// Clean up expired sessions.
    pub fn cleanup_expired_sessions(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();

        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, session| now - session.last_activity_ns < self.session_timeout_ns);
    }

    /// Get session statistics for monitoring.
    pub fn get_stats(&self) -> SessionStats {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let total_sessions = sessions.len();
        let active_sessions = sessions.values().filter(|s| s.escalation_score > 0).count();
        let high_risk_sessions = sessions
            .values()
            .filter(|s| s.escalation_score >= 70)
            .count();

        SessionStats {
            total_sessions,
            active_sessions,
            high_risk_sessions,
        }
    }

    // Private helper methods for escalation detection
    fn jaccard_similarity(&self, a: &str, b: &str) -> f32 {
        let set_a: std::collections::HashSet<&str> = a.split_whitespace().collect();
        let set_b: std::collections::HashSet<&str> = b.split_whitespace().collect();

        if set_a.is_empty() && set_b.is_empty() {
            return 1.0;
        }

        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();

        intersection as f32 / union as f32
    }

    fn is_complexity_escalation(&self, text: &str, previous_messages: &[SessionMessage]) -> bool {
        if previous_messages.is_empty() {
            return false;
        }

        // Check for increasing sentence length and complexity
        let avg_prev_length: usize = previous_messages
            .iter()
            .rev()
            .take(3) // Last 3 messages
            .map(|msg| msg.input_text.len())
            .sum::<usize>()
            / previous_messages.len().clamp(1, 3);

        let current_length = text.len();
        current_length > (avg_prev_length * 15) / 10 // 50% increase
    }

    fn is_topic_drift(&self, text: &str, previous_messages: &[SessionMessage]) -> bool {
        if previous_messages.is_empty() {
            return false;
        }

        // Determine a rough intent category for the *current* text using keyword signals.
        // We cannot run the full FSM here, so keyword heuristics are used instead.
        let lower = text.to_lowercase();
        let is_code_request = [
            "def ",
            "fn ",
            "function ",
            "class ",
            "```",
            "#!/",
            "import ",
            "var ",
            "let ",
            "const ",
        ]
        .iter()
        .any(|kw| lower.contains(kw));
        let is_translation_request = ["translate", "traduire", "traduce", "übersetze"]
            .iter()
            .any(|kw| lower.contains(kw));
        let is_factual_question = [
            "what is", "who is", "where is", "when is", "how does", "explain",
        ]
        .iter()
        .any(|kw| lower.contains(kw));

        // Compare the current text's inferred intent against the dominant previous intent.
        if let Some(last_intent) = previous_messages
            .iter()
            .rev()
            .find_map(|m| m.matched_intent.as_ref())
        {
            match last_intent {
                MatchedIntent::TaskCodeGeneration => {
                    // Was generating code; drift if current is clearly a question or translation.
                    (is_factual_question || is_translation_request) && !is_code_request
                }
                MatchedIntent::TaskTranslation => {
                    // Was translating; drift if now requesting code.
                    is_code_request && !is_translation_request
                }
                MatchedIntent::QuestionFactual
                | MatchedIntent::QuestionCausal
                | MatchedIntent::QuestionComparative => {
                    // Was asking factual questions; drift if now requesting code or
                    // accessing sensitive system paths (e.g. /etc/shadow, /proc/...).
                    let is_system_access = ["/etc/", "/proc/", "/sys/", "/root/", "/var/log/"]
                        .iter()
                        .any(|kw| lower.contains(kw));
                    (is_code_request || is_system_access) && !is_factual_question
                }
                _ => false,
            }
        } else {
            false
        }
    }

    fn is_policy_testing(&self, text: &str, previous_messages: &[SessionMessage]) -> bool {
        if previous_messages.is_empty() {
            return false;
        }

        // Check for high similarity with previous messages (Option A: Jaccard)
        for msg in previous_messages.iter().rev().take(3) {
            let similarity = self.jaccard_similarity(text, &msg.input_text);
            if similarity > 0.8 && similarity < 1.0 {
                // High similarity but not identical - user is likely probing/tweaking
                return true;
            }
        }

        false
    }

    fn is_repetition_with_variation(
        &self,
        text: &str,
        previous_messages: &[SessionMessage],
    ) -> bool {
        if previous_messages.is_empty() {
            return false;
        }

        // Check for medium similarity (variation on a theme)
        for msg in previous_messages.iter().rev().take(3) {
            let similarity = self.jaccard_similarity(text, &msg.input_text);
            if similarity > 0.5 && similarity <= 0.8 {
                return true;
            }
        }

        false
    }

    fn is_payload_fragmentation(&self, text: &str, previous_messages: &[SessionMessage]) -> bool {
        // Payload fragmentation often involves sending parts of a restricted keyword
        // or code snippet across multiple messages.

        // 1. Check for incomplete sentences/fragments.
        //    Only flag short non-terminated messages when there is already a conversation
        //    history (≥2 messages), to avoid false-positives on genuine one-liners.
        let text_trimmed = text.trim();
        if text_trimmed.is_empty() {
            return false;
        }

        let ends_with_punctuation = text_trimmed.ends_with('.')
            || text_trimmed.ends_with('!')
            || text_trimmed.ends_with('?');

        if !ends_with_punctuation && text_trimmed.len() < 15 && previous_messages.len() >= 2 {
            // Short, non-terminated string is suspicious when there is prior context.
            return true;
        }

        // 2. Check for unambiguous continuation indicators only.
        //    "next", "finally", "specifically" are too broad and cause false positives.
        let continuation_indicators = ["and then", "after that", "continued from"];
        for indicator in &continuation_indicators {
            if text.to_lowercase().contains(indicator) {
                return true;
            }
        }

        // 3. Check for suspected code/command fragments (e.g., unmatched braces).
        let open_braces = text.chars().filter(|&c| c == '{').count();
        let close_braces = text.chars().filter(|&c| c == '}').count();
        if open_braces != close_braces {
            return true;
        }

        false
    }

    fn is_rapid_escalation(&self, session: &SessionContext) -> bool {
        if session.messages.len() < 3 {
            return false;
        }

        // Check if escalation score increased rapidly in last 3 messages
        let recent_indicators: usize = session
            .messages
            .iter()
            .rev()
            .take(3)
            .map(|msg| msg.escalation_indicators.len())
            .sum::<usize>();

        recent_indicators >= 3 // 3+ indicators in last 3 messages
    }

    fn generate_recommendations(
        &self,
        risk_level: &SessionRiskLevel,
        flags: &[SessionFlag],
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        match risk_level {
            SessionRiskLevel::High => {
                recommendations.push("Consider session termination or human review".to_string());
                recommendations.push("Implement rate limiting for this session".to_string());
            }
            SessionRiskLevel::Medium => {
                recommendations.push("Monitor session closely for escalation".to_string());
                recommendations.push("Consider increasing scrutiny of future requests".to_string());
            }
            SessionRiskLevel::Low => {
                recommendations.push("Continue normal monitoring".to_string());
            }
        }

        for flag in flags {
            match flag {
                SessionFlag::FragmentationDetected => {
                    recommendations.push("Potential payload fragmentation detected".to_string());
                }
                SessionFlag::TopicDriftDetected => {
                    recommendations.push("Abrupt topic drift detected — possible intent masking".to_string());
                }
                SessionFlag::RapidEscalation => {
                    recommendations.push("Rapid escalation pattern detected".to_string());
                }
                SessionFlag::LongSession => {
                    recommendations
                        .push("Long session may indicate sophisticated probing".to_string());
                }
                SessionFlag::HighEscalationScore => {
                    recommendations.push("High escalation score requires attention".to_string());
                }
            }
        }

        recommendations
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Analysis result for a message within session context.
#[derive(Debug, Clone)]
pub struct SessionAnalysis {
    pub session_id: String,
    pub risk_level: SessionRiskLevel,
    pub escalation_score: u8,
    pub flags: Vec<SessionFlag>,
    pub message_count: usize,
    pub session_duration_ns: u128,
    pub recommendations: Vec<String>,
}

/// Session risk level classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRiskLevel {
    Low,
    Medium,
    High,
}

/// Session flags indicating specific concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionFlag {
    HighEscalationScore,
    FragmentationDetected,
    TopicDriftDetected,
    RapidEscalation,
    LongSession,
}

/// Session statistics for monitoring.
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub high_risk_sessions: usize,
}

// Global session manager instance
static SESSION_MANAGER: OnceLock<SessionManager> = OnceLock::new();

/// Initialize the global session manager.
pub fn init_session_manager() {
    let _ = SESSION_MANAGER.get_or_init(SessionManager::new);
}

/// Get the global session manager.
pub fn get_session_manager() -> Option<&'static SessionManager> {
    SESSION_MANAGER.get()
}

/// Evaluate message with session context (enhanced version of evaluate_raw).
pub fn evaluate_with_session(
    session_id: &str,
    input: &mut PromptInput,
    sequence: u64,
) -> crate::types::Verdict {
    // First, get the base firewall verdict
    let base_verdict = crate::evaluate(input, sequence);

    // Then, analyze with session context
    if let Some(session_manager) = get_session_manager() {
        // Extract matched intent from either channel (Pillar 1: Deterministic Safety)
        let matched_intent = match &base_verdict.channel_a.decision {
            ChannelDecision::Pass { intent } => Some(intent.clone()),
            _ => match &base_verdict.channel_b.decision {
                ChannelDecision::Pass { intent } => Some(intent.clone()),
                _ => None,
            },
        };

        let session_analysis = session_manager.add_message(
            session_id,
            input,
            base_verdict.kind.clone(),
            base_verdict.audit.block_reason.clone(),
            matched_intent,
        );

        // For now, session analysis is advisory only
        // In production, high-risk sessions could trigger additional safeguards
        if session_analysis.risk_level == SessionRiskLevel::High {
            // Log high-risk session for operator review
            eprintln!(
                "Session Risk Alert: {} - Score: {}, Flags: {:?}",
                session_analysis.session_id,
                session_analysis.escalation_score,
                session_analysis.flags
            );
        }
    }

    base_verdict
}

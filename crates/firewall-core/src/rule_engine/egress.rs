// rule_engine/egress.rs — Channel F: Rule-based Egress for output validation
//
// Specialized in:
// 1. Obfuscated Leakage Detection (High entropy / Base64 / Hex patterns)
// 2. Prohibited Framing (Detecting "As an AI model...", "Here is the secret key:")

use crate::types::{ChannelDecision, ChannelId, ChannelResult, PromptInput};

pub struct ChannelF;

impl ChannelF {
    pub fn evaluate(prompt: &PromptInput, response: &str) -> ChannelResult {
        let start = std::time::Instant::now();

        // 1. Anchor Validation (SA-080)
        // High-confidence enforcement of context-aware egress constraints.
        if let Some(anchor) = prompt.matched_intent.as_ref().map(|i| i.expected_anchor()) {
            match anchor {
                crate::types::EgressAnchor::TextOnly => {
                    // Block Markdown code blocks in TextOnly mode (RE-E01-01)
                    if response.contains("```") || response.contains("~~~") {
                        return ChannelResult {
                            channel: ChannelId::F,
                            decision: ChannelDecision::Block {
                                reason: crate::types::BlockReason::AnchorViolation {
                                    detail: "Code block detected in TextOnly response (RE-E01-01)".to_string(),
                                },
                            },
                            elapsed_us: start.elapsed().as_micros() as u64,
                            similarity: None,
                        };
                    }
                }
                crate::types::EgressAnchor::Structured => {
                    // Advisory: Check if it's actually JSON if structured was requested (RE-E02-01)
                    if serde_json::from_str::<serde_json::Value>(response).is_err() {
                        // Diagnostic only - we don't hard block malformed JSON unless configured (v1.1 goal).
                    }
                }
                _ => {}
            }
        }

        // 2. Obfuscated Leakage: Look for Base64/Hex buffers that might leak secrets
        if let Some(obfuscated) = detect_obfuscated_data(response) {
            // SA-080-HL: If we are in TextOnly mode, high entropy is Advisory (unless strictness is bumped)
            let is_text_only = prompt.matched_intent.as_ref()
                .map(|i| matches!(i.expected_anchor(), crate::types::EgressAnchor::TextOnly))
                .unwrap_or(false);

            if !is_text_only {
                // Hard block for non-text-only modes (standard Pillar 6 behavior)
                return ChannelResult {
                    channel: ChannelId::F,
                    decision: ChannelDecision::Block {
                        reason: crate::types::BlockReason::MalformedInput {
                            detail: format!("Obfuscated/Encoded data detected: {}", obfuscated),
                        },
                    },
                    elapsed_us: start.elapsed().as_micros() as u64,
                    similarity: None,
                };
            }
        }

        // 2. Prohibited Framing: Rejection of stereotypical leak patterns
        let framing_patterns = [
            "the system prompt",
            "the hidden instructions",
            "here is the secret key",
            "secret_key =",
            "private_key =",
        ];

        let lower_response = response.to_lowercase();
        for pattern in framing_patterns {
            if lower_response.contains(pattern) {
                return ChannelResult {
                    channel: ChannelId::F,
                    decision: ChannelDecision::Block {
                        reason: crate::types::BlockReason::ForbiddenPattern {
                            pattern_id: format!(
                                "EGRESS-RE-001-{}",
                                pattern.replace(' ', "-").to_uppercase()
                            ),
                        },
                    },
                    elapsed_us: start.elapsed().as_micros() as u64,
                    similarity: None,
                };
            }
        }

        ChannelResult {
            channel: ChannelId::F,
            decision: ChannelDecision::Pass {
                intent: crate::types::MatchedIntent::ConversationalAcknowledgement,
            },
            elapsed_us: start.elapsed().as_micros() as u64,
            similarity: None,
        }
    }
}

fn detect_obfuscated_data(text: &str) -> Option<&'static str> {
    // Detect potential Base64 blobs (> 32 chars of Base64 set)
    let b64_count = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    if b64_count > 64 && text.len() > 64 {
        // High density check
        let density = b64_count as f32 / text.len() as f32;
        if density > 0.9 {
            return Some("Potential Base64/Encoded data");
        }
    }
    None
}

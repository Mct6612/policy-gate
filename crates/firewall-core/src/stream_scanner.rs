// stream_scanner.rs — SA-NEW: Streaming Egress Scanner (Pillar 6)
//
// Provides an Aho-Corasick-based streaming egress scanner that detects PII,
// secrets, and prohibited framing patterns across SSE chunk boundaries.
//
// Design invariants:
//   - The overlap buffer (STREAM_EGRESS_OVERLAP_BYTES) guarantees that any
//     pattern with an anchor length ≤ STREAM_EGRESS_MAX_PATTERN_BYTES is
//     detected even if it straddles two consecutive SSE chunks.
//   - The searcher is compiled once at init() and shared (Arc) across
//     connections — zero per-request compilation cost.
//   - Each open streaming connection owns its own StreamScanner instance
//     (cheap: only the overlap buffer lives per-connection; the heavy
//     AhoCorasick state machine is reference-counted).
//   - This module is only compiled when the `streaming-egress` feature is active.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::sync::{Arc, OnceLock};

/// Size of the tail overlap buffer in bytes.
/// Must be ≥ (longest_pattern_anchor_bytes - 1).
/// Current value: 256 bytes (covers all built-in patterns; custom patterns
/// must not exceed STREAM_EGRESS_MAX_PATTERN_BYTES — validated at config load).
pub const STREAM_EGRESS_OVERLAP_BYTES: usize = 256;

/// Maximum allowed anchor length for custom egress patterns when
/// `streaming_egress_enabled = true`. Enforced in `FirewallConfig::validate()`.
pub const STREAM_EGRESS_MAX_PATTERN_BYTES: usize = 127;

/// Decision returned by `StreamScanner::feed()` for each chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEgressDecision {
    /// No match found — forward this chunk to the client.
    Forward,
    /// Match found — block the stream immediately.
    Block {
        /// Identifier of the matching pattern (for audit and Prometheus label).
        pattern_id: &'static str,
    },
}

/// Built-in patterns compiled into every StreamScanner.
/// These are fixed-string anchors derived from the existing egress channel
/// implementations (ChannelE / ChannelF / egress_structured.rs).
///
/// All anchors are ≤ STREAM_EGRESS_MAX_PATTERN_BYTES bytes.
pub(crate) static BUILTIN_PATTERNS: &[(&str, &str)] = &[
    // ── ChannelF framing patterns ────────────────────────────────────────────
    ("EGRESS-SF-001", "the system prompt"),
    ("EGRESS-SF-002", "the hidden instructions"),
    ("EGRESS-SF-003", "here is the secret key"),
    ("EGRESS-SF-004", "secret_key ="),
    ("EGRESS-SF-005", "private_key ="),
    // ── Secret / API key prefixes (ChannelE supplement) ──────────────────────
    ("EGRESS-SF-010", "sk-"),          // OpenAI API key prefix
    ("EGRESS-SF-011", "sk-proj-"),     // OpenAI project key prefix
    ("EGRESS-SF-012", "ghp_"),         // GitHub personal access token
    ("EGRESS-SF-013", "ghs_"),         // GitHub app token
    ("EGRESS-SF-014", "-----BEGIN"),   // PEM header (private key, cert, etc.)
    // ── egress_structured.rs JSON field anchors ───────────────────────────────
    ("EGRESS-SF-020", r#""private_key""#),
    ("EGRESS-SF-021", r#""api_key""#),
    ("EGRESS-SF-022", r#""database_url""#),
    ("EGRESS-SF-023", r#""db_url""#),
    ("EGRESS-SF-024", r#""apikey""#),
];

/// Per-connection streaming egress scanner.
///
/// Cheap to clone (the AhoCorasick automaton is reference-counted).
/// The overlap buffer is stack-allocated per instance.
pub struct StreamScanner {
    /// Pre-compiled multi-pattern searcher (shared across connections).
    searcher: Arc<AhoCorasick>,
    /// Map from pattern index to its static identifier.
    pattern_ids: Arc<Vec<&'static str>>,
    /// Tail of the previous chunk (for cross-boundary detection).
    overlap: [u8; STREAM_EGRESS_OVERLAP_BYTES],
    /// Number of valid bytes at the start of `overlap`.
    overlap_len: usize,
}

impl StreamScanner {
    /// Create a new scanner from the built-in pattern set.
    /// Panics if the Aho-Corasick automaton cannot be compiled (should never
    /// happen with the built-in patterns; verified in tests).
    pub fn new() -> Self {
        Self::from_global()
    }

    /// Create a scanner that borrows the global AhoCorasick searcher.
    fn from_global() -> Self {
        let (searcher, pattern_ids) = global_searcher();
        StreamScanner {
            searcher: Arc::clone(searcher),
            pattern_ids: Arc::clone(pattern_ids),
            overlap: [0u8; STREAM_EGRESS_OVERLAP_BYTES],
            overlap_len: 0,
        }
    }

    /// Feed a raw SSE chunk into the scanner.
    ///
    /// The scanner combines the tail of the previous chunk (overlap buffer)
    /// with the new chunk, then searches for any registered pattern.
    ///
    /// Returns `StreamEgressDecision::Block` immediately on the first match.
    /// Returns `StreamEgressDecision::Forward` if no match is found, and
    /// updates the overlap buffer for the next call.
    pub fn feed(&mut self, chunk: &[u8]) -> StreamEgressDecision {
        // Fast path: if both overlap and chunk are empty, nothing to scan.
        if self.overlap_len == 0 && chunk.is_empty() {
            return StreamEgressDecision::Forward;
        }

        // Build the combined view.
        // For small chunks (≤ 4 KB) we avoid a heap allocation by using a
        // fixed-size stack buffer. For larger chunks we fall back to Vec.
        let combined_len = self.overlap_len + chunk.len();

        // We always scan the full combined view.
        let decision = if combined_len <= 4096 {
            let mut buf = [0u8; 4096];
            buf[..self.overlap_len].copy_from_slice(&self.overlap[..self.overlap_len]);
            buf[self.overlap_len..combined_len].copy_from_slice(chunk);
            self.scan_bytes(&buf[..combined_len])
        } else {
            let mut combined = Vec::with_capacity(combined_len);
            combined.extend_from_slice(&self.overlap[..self.overlap_len]);
            combined.extend_from_slice(chunk);
            self.scan_bytes(&combined)
        };

        if decision == StreamEgressDecision::Forward {
            // Update overlap: keep the last min(OVERLAP, combined_len) bytes.
            let tail_len = chunk.len().min(STREAM_EGRESS_OVERLAP_BYTES);
            let tail_start = chunk.len() - tail_len;
            self.overlap[..tail_len].copy_from_slice(&chunk[tail_start..]);
            self.overlap_len = tail_len;
        }

        decision
    }

    /// Reset the overlap buffer (call between logical streams / reconnects).
    pub fn reset(&mut self) {
        self.overlap_len = 0;
    }

    fn scan_bytes(&self, data: &[u8]) -> StreamEgressDecision {
        match self.searcher.find(data) {
            Some(m) => {
                let id = self.pattern_ids.get(m.pattern().as_usize())
                    .copied()
                    .unwrap_or("EGRESS-SF-UNKNOWN");
                StreamEgressDecision::Block { pattern_id: id }
            }
            None => StreamEgressDecision::Forward,
        }
    }
}

impl Default for StreamScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Global searcher (compiled once at init) ──────────────────────────────────

static GLOBAL_SEARCHER: OnceLock<(Arc<AhoCorasick>, Arc<Vec<&'static str>>)> = OnceLock::new();

/// Initialise the global Aho-Corasick searcher.
/// Called from `firewall_core::init()` when the `streaming-egress` feature is active.
///
/// # Errors
/// Returns `Err` if the automaton fails to compile (should never happen with
/// the built-in patterns).
pub fn init_global_scanner() -> Result<(), String> {
    GLOBAL_SEARCHER.get_or_init(|| {
        let patterns: Vec<&str> = BUILTIN_PATTERNS.iter().map(|(_, p)| *p).collect();
        let ids: Vec<&'static str> = BUILTIN_PATTERNS.iter().map(|(id, _)| *id).collect();
        let searcher = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .ascii_case_insensitive(true)  // catches "The System Prompt", "SECRET_KEY =", etc.
            .build(&patterns)
            .expect("StreamScanner: failed to compile Aho-Corasick automaton");
        (Arc::new(searcher), Arc::new(ids))
    });
    Ok(())
}

fn global_searcher() -> &'static (Arc<AhoCorasick>, Arc<Vec<&'static str>>) {
    GLOBAL_SEARCHER
        .get()
        .expect("StreamScanner: global searcher not initialised — call init_global_scanner() first")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scanner() -> StreamScanner {
        init_global_scanner().expect("init failed");
        StreamScanner::new()
    }

    #[test]
    fn scanner_detects_pattern_within_single_chunk() {
        let mut s = make_scanner();
        let chunk = b"The result is: sk-live-abc123456789";
        assert_eq!(
            s.feed(chunk),
            StreamEgressDecision::Block { pattern_id: "EGRESS-SF-010" }
        );
    }

    #[test]
    fn scanner_detects_pattern_across_chunk_boundary() {
        let mut s = make_scanner();
        // Pattern "sk-" split: "sk" in first chunk, "-" in second.
        let chunk1 = b"The api key ends with sk";
        let chunk2 = b"-live-abc123";
        assert_eq!(s.feed(chunk1), StreamEgressDecision::Forward);
        assert_eq!(
            s.feed(chunk2),
            StreamEgressDecision::Block { pattern_id: "EGRESS-SF-010" }
        );
    }

    #[test]
    fn scanner_no_false_positive_on_partial_prefix_at_end() {
        let mut s = make_scanner();
        // "sk" alone at end of chunk — not a match yet.
        let chunk1 = b"This token ends with sk";
        assert_eq!(s.feed(chunk1), StreamEgressDecision::Forward);
        // Next chunk has no continuation of a pattern.
        let chunk2 = b"ipping the rest of the sentence.";
        assert_eq!(s.feed(chunk2), StreamEgressDecision::Forward);
    }

    #[test]
    fn scanner_overlap_buffer_does_not_overflow_on_large_chunk() {
        let mut s = make_scanner();
        let large_clean = vec![b'a'; 8192];
        assert_eq!(s.feed(&large_clean), StreamEgressDecision::Forward);
        assert!(s.overlap_len <= STREAM_EGRESS_OVERLAP_BYTES);
    }

    #[test]
    fn scanner_detects_pem_header_across_boundary() {
        let mut s = make_scanner();
        // "-----BEGIN" split: "-----" in chunk1, "BEGIN" in chunk2.
        let chunk1 = b"Here is the key:\n-----";
        let chunk2 = b"BEGIN RSA PRIVATE KEY-----\nMIIE...";
        assert_eq!(s.feed(chunk1), StreamEgressDecision::Forward);
        assert_eq!(
            s.feed(chunk2),
            StreamEgressDecision::Block { pattern_id: "EGRESS-SF-014" }
        );
    }

    #[test]
    fn scanner_detects_json_field_anchor() {
        let mut s = make_scanner();
        let chunk = br#"{"user": "alice", "api_key": "sk-abc"}"#;
        // "api_key" field anchor triggers first (leftmost match)
        let decision = s.feed(chunk);
        assert!(matches!(decision, StreamEgressDecision::Block { .. }));
    }

    #[test]
    fn scanner_case_insensitive_framing() {
        let mut s = make_scanner();
        let chunk = b"Sure! Here Is The Secret Key: abc123";
        assert_eq!(
            s.feed(chunk),
            StreamEgressDecision::Block { pattern_id: "EGRESS-SF-003" }
        );
    }

    #[test]
    fn scanner_reset_clears_overlap() {
        let mut s = make_scanner();
        // Put "sk" into overlap
        assert_eq!(s.feed(b"ends with sk"), StreamEgressDecision::Forward);
        assert!(s.overlap_len > 0);
        s.reset();
        assert_eq!(s.overlap_len, 0);
        // Now the "-live-..." chunk should not trigger (no overlap context)
        assert_eq!(s.feed(b"-live-abc"), StreamEgressDecision::Forward);
    }

    #[test]
    fn builtin_patterns_all_within_max_length() {
        for (id, pattern) in BUILTIN_PATTERNS {
            assert!(
                pattern.len() <= STREAM_EGRESS_MAX_PATTERN_BYTES,
                "Built-in pattern {id} is {} bytes — exceeds STREAM_EGRESS_MAX_PATTERN_BYTES ({})",
                pattern.len(),
                STREAM_EGRESS_MAX_PATTERN_BYTES
            );
        }
    }
}

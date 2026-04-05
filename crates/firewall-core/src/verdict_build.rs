use crate::advisory;
use crate::audit::{attach_chain_hmac, sha256_hex};
use crate::review::track_review_item;
use crate::types::{
    AdvisoryTag, AuditDetailLevel, AuditEntry, BlockReason, ChannelDecision, ChannelResult,
    PromptInput, Verdict, VerdictKind,
};

pub(crate) fn advisory_tag(
    event: &advisory::AdvisoryEvent,
) -> AdvisoryTag {
    match event {
        advisory::AdvisoryEvent::AdvisoryDisagreement {
            score,
            heuristic_version,
            ..
        } => AdvisoryTag::Disagreement {
            score: *score,
            heuristic_version: *heuristic_version,
        },
        advisory::AdvisoryEvent::AdvisoryFault { .. } => AdvisoryTag::Fault,
        advisory::AdvisoryEvent::None => AdvisoryTag::None,
    }
}

pub(crate) fn block_reason(
    verdict_kind: &VerdictKind,
    channel_a: &ChannelResult,
    channel_b: &ChannelResult,
) -> Option<BlockReason> {
    match verdict_kind {
        VerdictKind::Pass | VerdictKind::DiagnosticAgreement => None,
        VerdictKind::Block | VerdictKind::DiagnosticDisagreement | VerdictKind::EgressBlock | VerdictKind::ShadowPass => {
            match &channel_a.decision {
                ChannelDecision::Block { reason } => Some(reason.clone()),
                ChannelDecision::Fault { .. } => match &channel_b.decision {
                    ChannelDecision::Block { reason } => Some(reason.clone()),
                    _ => None,
                },
                _ => match &channel_b.decision {
                    ChannelDecision::Block { reason } => Some(reason.clone()),
                    _ => None,
                },
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_final_verdict(
    input: &PromptInput,
    sequence: u64,
    verdict_kind: VerdictKind,
    advisory_tag: AdvisoryTag,
    decided_ns: u128,
    total_us: u64,
    channel_a: ChannelResult,
    channel_b: ChannelResult,
    #[cfg(feature = "semantic")] channel_d: ChannelResult,
    #[cfg(feature = "semantic")] semantic_similarity: Option<f32>,
    #[cfg(not(feature = "semantic"))] _semantic_similarity: Option<f32>,
    audit_detail_level: AuditDetailLevel,
    tenant_id: Option<String>,
) -> Verdict {
    let block_reason = block_reason(&verdict_kind, &channel_a, &channel_b);
    let input_hash = sha256_hex(&input.text);

    let audit = match audit_detail_level {
        AuditDetailLevel::Detailed => AuditEntry::detailed(
            sequence,
            verdict_kind.clone(),
            block_reason,
            input_hash,
            advisory_tag,
            #[cfg(feature = "semantic")]
            semantic_similarity,
            #[cfg(not(feature = "semantic"))]
            None,
            None,
            None,
            None,
            input.ingested_at_ns,
            decided_ns,
            total_us,
            channel_a.clone(),
            channel_b.clone(),
            tenant_id.clone(),
        ),
        AuditDetailLevel::Basic => AuditEntry::basic(
            sequence,
            verdict_kind.clone(),
            block_reason,
            input_hash,
            advisory_tag,
            #[cfg(feature = "semantic")]
            semantic_similarity,
            #[cfg(not(feature = "semantic"))]
            None,
            None,
            None,
            None,
            input.ingested_at_ns,
            decided_ns,
            total_us,
            tenant_id,
        ),
    };

    let mut final_audit = audit;
    attach_chain_hmac(&mut final_audit);

    let final_verdict = Verdict {
        kind: verdict_kind,
        channel_a,
        channel_b,
        #[cfg(feature = "semantic")]
        channel_d: Some(channel_d),
        #[cfg(not(feature = "semantic"))]
        channel_d: None,
        audit: final_audit,
    };

    track_review_item(&final_verdict);
    final_verdict
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_final_verdict_from_cache(
    raw: &str,
    sequence: u64,
    verdict_kind: VerdictKind,
    advisory_tag: AdvisoryTag,
    decided_ns: u128,
    total_us: u64,
    channel_a_decision: ChannelDecision,
    channel_b_decision: ChannelDecision,
    audit_detail_level: AuditDetailLevel,
    tenant_id: Option<String>,
) -> Verdict {
    let channel_a = ChannelResult {
        channel: crate::types::ChannelId::A,
        decision: channel_a_decision,
        elapsed_us: 0, // Cached hit
        similarity: None,
    };
    let channel_b = ChannelResult {
        channel: crate::types::ChannelId::B,
        decision: channel_b_decision,
        elapsed_us: 0, // Cached hit
        similarity: None,
    };

    let block_reason = block_reason(&verdict_kind, &channel_a, &channel_b);
    let input_hash = sha256_hex(raw);

    let audit = match audit_detail_level {
        AuditDetailLevel::Detailed | AuditDetailLevel::Basic => AuditEntry::basic(
            sequence,
            verdict_kind.clone(),
            block_reason,
            input_hash,
            advisory_tag,
            None,
            None,
            None,
            None,
            decided_ns - (total_us as u128 * 1_000), // Approximate ingested_at
            decided_ns,
            total_us,
            tenant_id,
        ),
    };

    let mut final_audit = audit;
    attach_chain_hmac(&mut final_audit);

    Verdict {
        kind: verdict_kind,
        channel_a,
        channel_b,
        channel_d: None, // Semantic channel is bypassed on cache hit
        audit: final_audit,
    }
}

use crate::audit::{attach_chain_hmac, sha256_hex};
use crate::types::{
    AdvisoryTag, AuditEntry, BlockReason, ChannelDecision, EgressBlockReason, EgressVerdict,
    PromptInput, VerdictKind,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos()
}

fn egress_reason(
    channel_e: &crate::ChannelResult,
    channel_f: &crate::ChannelResult,
    verdict_kind: &VerdictKind,
) -> Option<EgressBlockReason> {
    if *verdict_kind != VerdictKind::EgressBlock {
        return None;
    }

    let blocking = if matches!(channel_e.decision, ChannelDecision::Block { .. }) {
        &channel_e.decision
    } else {
        &channel_f.decision
    };

    match blocking {
        ChannelDecision::Block { reason } => Some(match reason {
            BlockReason::MalformedInput { detail } => {
                if detail.starts_with("PII") {
                    EgressBlockReason::PiiDetected {
                        pii_type: detail.clone(),
                    }
                } else {
                    EgressBlockReason::SystemPromptLeakage {
                        detail: detail.clone(),
                    }
                }
            }
            BlockReason::ForbiddenPattern { pattern_id } => EgressBlockReason::HarmfulContent {
                category: pattern_id.clone(),
            },
            other => EgressBlockReason::Other {
                detail: format!("{:?}", other),
            },
        }),
        _ => None,
    }
}

pub(crate) fn evaluate_output(
    prompt: &PromptInput,
    response: &str,
    sequence: u64,
    tenant_id: Option<&str>,
) -> EgressVerdict {
    let channel_e = crate::fsm::egress::ChannelE::evaluate(prompt, response);
    let channel_f = crate::rule_engine::egress::ChannelF::evaluate(prompt, response);

    let mut verdict_kind = match (&channel_e.decision, &channel_f.decision) {
        (ChannelDecision::Pass { .. }, ChannelDecision::Pass { .. }) => VerdictKind::Pass,
        _ => VerdictKind::EgressBlock,
    };

    let egress_reason = egress_reason(&channel_e, &channel_f, &verdict_kind);

    if crate::init::get_config_for_tenant(tenant_id).and_then(|c| c.shadow_mode).unwrap_or(false)
        && verdict_kind == VerdictKind::EgressBlock
    {
        verdict_kind = VerdictKind::ShadowPass;
    }

    let decided_ns = now_ns();
    let mut audit = AuditEntry::basic(
        sequence,
        verdict_kind.clone(),
        None,
        sha256_hex(&prompt.text),
        AdvisoryTag::None,
        None,
        None,
        Some(verdict_kind.clone()),
        egress_reason.clone(),
        prompt.ingested_at_ns,
        decided_ns,
        ((decided_ns - prompt.ingested_at_ns) / 1_000).min(u64::MAX as u128) as u64,
        tenant_id.map(|s| s.to_string()),
    );

    attach_chain_hmac(&mut audit);

    EgressVerdict {
        kind: verdict_kind.clone(),
        egress_verdict: verdict_kind,
        egress_reason,
        audit: Some(audit),
    }
}

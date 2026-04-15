use crate::advisory;
use crate::config;
use crate::config::OnDiagnosticAgreement;
use crate::fsm::ChannelA;
use crate::init::get_config_for_tenant;
use crate::rule_engine::ChannelB;
use crate::types::{
    AuditDetailLevel, BlockReason, ChannelDecision, PromptInput, Verdict, VerdictKind,
};
use crate::verdict_build::{advisory_tag as build_advisory_tag, build_final_verdict};
use crate::voter::Voter;

fn apply_profile_filter(
    verdict_kind: &mut VerdictKind,
    channel_a: &mut crate::ChannelResult,
    channel_b: &mut crate::ChannelResult,
    config: Option<&config::FirewallConfig>,
) {
    if !matches!(
        verdict_kind,
        VerdictKind::Pass | VerdictKind::DiagnosticAgreement
    ) {
        return;
    }

    if let Some(permitted) = config.and_then(|c| c.permitted_intents.as_ref()) {
        let matched_intent = match &channel_a.decision {
            ChannelDecision::Pass { intent } => Some(intent),
            _ => match &channel_b.decision {
                ChannelDecision::Pass { intent } => Some(intent),
                _ => None,
            },
        };

        if let Some(intent) = matched_intent {
            if !permitted.contains(intent) {
                *verdict_kind = VerdictKind::Block;
                let reason = BlockReason::ProhibitedIntent {
                    intent: intent.clone(),
                };
                channel_a.decision = ChannelDecision::Block {
                    reason: reason.clone(),
                };
                channel_b.decision = ChannelDecision::Block { reason };
            }
        }
    }
}

fn audit_detail_level(config: Option<&config::FirewallConfig>) -> AuditDetailLevel {
    config
        .and_then(|c: &config::FirewallConfig| c.audit_detail_level)
        .unwrap_or(AuditDetailLevel::Basic)
}

/// Synthesises a block verdict for unknown/anonymous tenants.
fn unknown_tenant_block(
    input: &PromptInput,
    sequence: u64,
    now: u128,
    tenant_id: Option<String>,
) -> Verdict {
    let reason = BlockReason::UnknownTenant;
    let block = crate::types::ChannelResult {
        channel: crate::types::ChannelId::A,
        decision: ChannelDecision::Block {
            reason: reason.clone(),
        },
        elapsed_us: 0,
        similarity: None,
    };
    let block_b = crate::types::ChannelResult {
        channel: crate::types::ChannelId::B,
        decision: ChannelDecision::Block {
            reason: reason.clone(),
        },
        elapsed_us: 0,
        similarity: None,
    };
    build_final_verdict(
        input,
        sequence,
        VerdictKind::Block,
        crate::types::AdvisoryTag::None,
        now,
        0,
        block,
        block_b,
        #[cfg(feature = "semantic")]
        crate::types::ChannelResult {
            channel: crate::types::ChannelId::D,
            decision: crate::types::ChannelDecision::Pass {
                intent: crate::types::MatchedIntent::QuestionFactual,
            },
            elapsed_us: 0,
            similarity: None,
        },
        #[cfg(feature = "semantic")]
        None,
        #[cfg(not(feature = "semantic"))]
        None,
        AuditDetailLevel::Basic,
        tenant_id,
    )
}

pub(crate) fn evaluate(
    input: &mut PromptInput,
    sequence: u64,
    tenant_id: Option<&str>,
    now_ns: fn() -> u128,
) -> Verdict {
    let start_ns = now_ns();
    let config = get_config_for_tenant(tenant_id);

    // Pillar 5: Fail-Closed for unknown or unauthorized tenants.
    if config.is_none() {
        return unknown_tenant_block(&input, sequence, start_ns, tenant_id.map(|s| s.to_string()));
    }

    // If no specific tenant provided, only allow access if anonymous is enabled (or not explicitly disabled) in the default policy.
    if tenant_id.is_none() && config.as_ref().and_then(|c| c.allow_anonymous_tenants) == Some(false)
    {
        return unknown_tenant_block(&input, sequence, start_ns, None);
    }

    let mut channel_a = ChannelA::evaluate(&input, config.as_ref());
    let mut channel_b = ChannelB::evaluate(&input, config.as_ref());

    #[cfg(feature = "semantic")]
    let (s_tag, s_enf, s_mode) = config
        .as_ref()
        .map(|c| {
            (
                c.semantic_threshold.unwrap_or(0.60),
                c.semantic_enforce_threshold.unwrap_or(1.0),
                c.engine_mode.as_deref().unwrap_or("fast"),
            )
        })
        .unwrap_or((0.60, 1.0, "fast"));

    #[cfg(feature = "semantic")]
    let channel_d = crate::semantic::ChannelD::evaluate(&input.text, s_tag, s_enf, s_mode);
    #[cfg(feature = "semantic")]
    let semantic_similarity = channel_d.similarity;
    #[cfg(not(feature = "semantic"))]
    let _semantic_similarity: Option<f32> = None;

    let mut verdict_kind = Voter::decide(&channel_a, &channel_b);

    // SA-NEW: Per-tenant DiagnosticAgreement escalation.
    // If the tenant has configured `on_diagnostic_agreement = "fail_closed"`,
    // we immediately escalate the intent-mismatch Pass to a hard Block.
    // This is the correct hardening posture for high-sensitivity tenants
    // (e.g. financial data, PII) where any ambiguity must fail closed.
    if verdict_kind == VerdictKind::DiagnosticAgreement {
        let policy = config
            .as_ref()
            .map(|c| c.on_diagnostic_agreement)
            .unwrap_or(OnDiagnosticAgreement::PassAndLog);
        if policy == OnDiagnosticAgreement::FailClosed {
            verdict_kind = VerdictKind::Block;
        }
    }

    #[cfg(feature = "semantic")]
    {
        if let ChannelDecision::Block { .. } = &channel_d.decision {
            verdict_kind = VerdictKind::Block;
        }
    }

    // SA-080: Extract and persist the winning intent for context-aware egress anchors.
    // In a 1oo2 system, if they disagree on intent but both pass, we log DiagnosticAgreement.
    // We prefer Channel A's intent for the anchor, as it's the primary system FSM.
    let final_intent = match (&channel_a.decision, &channel_b.decision) {
        (ChannelDecision::Pass { intent }, _) => Some(intent.clone()),
        (_, ChannelDecision::Pass { intent }) => Some(intent.clone()),
        _ => None,
    };
    input.matched_intent = final_intent;

    apply_profile_filter(
        &mut verdict_kind,
        &mut channel_a,
        &mut channel_b,
        config.as_ref(),
    );

    if config.as_ref().and_then(|c| c.shadow_mode).unwrap_or(false)
        && !matches!(
            verdict_kind,
            VerdictKind::Pass | VerdictKind::DiagnosticAgreement
        )
    {
        verdict_kind = VerdictKind::ShadowPass;
    }

    let mut advisory_opinion = advisory::ChannelC::evaluate(&input.text);

    // SA-079: Enhance advisory opinion with structured input analysis.
    // If the input contains structured data (JSON/YAML/templates) with variable
    // substitution patterns or sensitive field names, escalate to Suspicious.
    // This is advisory-only — does not affect the core pass/block verdict.
    if matches!(advisory_opinion, advisory::AdvisoryOpinion::Safe) {
        if let Some(meta) = crate::structured::detect_structured_input(input) {
            if meta.has_variable_refs || !meta.sensitive_field_names.is_empty() {
                advisory_opinion = advisory::AdvisoryOpinion::Suspicious {
                    score: 1,
                    reason: "structured input with variable refs or sensitive field names (SA-079)",
                };
            }
        }
    }

    let advisory_event = advisory::ChannelC::audit_event(&advisory_opinion, &verdict_kind);
    let advisory_tag = build_advisory_tag(&advisory_event);

    let decided_ns = now_ns();
    let total_us = ((decided_ns - start_ns) / 1_000).min(u64::MAX as u128) as u64;

    build_final_verdict(
        &input,
        sequence,
        verdict_kind,
        advisory_tag,
        decided_ns,
        total_us,
        channel_a,
        channel_b,
        #[cfg(feature = "semantic")]
        channel_d,
        #[cfg(feature = "semantic")]
        semantic_similarity,
        #[cfg(not(feature = "semantic"))]
        None,
        audit_detail_level(config.as_ref()),
        tenant_id.map(|s| s.to_string()),
    )
}

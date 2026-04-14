use firewall_core::{init, PromptInput, evaluate, evaluate_output, VerdictKind, EgressBlockReason, MatchedIntent};

#[test]
fn test_sa_080_translation_blocks_code() {
    init().expect("init failed");

    // 1. Ingress: Request translation
    let mut prompt = PromptInput::new("Please translate 'Hello' to German.").expect("new failed");
    let v_ingress = evaluate(&mut prompt, 1);
    
    assert!(v_ingress.is_pass());
    // Verify intent was persisted
    assert_eq!(prompt.matched_intent, Some(MatchedIntent::TaskTranslation));

    // 2. Egress: LLM responds with code block (Violation)
    let response = "Here is the translation: ```print('Hallo')```";
    let v_egress = evaluate_output(&prompt, response, 1).expect("eval_output failed");

    assert_eq!(v_egress.kind, VerdictKind::EgressBlock);
    assert!(matches!(v_egress.egress_reason, Some(EgressBlockReason::AnchorViolation { .. })));
}

#[test]
fn test_sa_080_code_intent_allows_code() {
    init().expect("init failed");

    // 1. Ingress: Request code
    let mut prompt = PromptInput::new("Write a function that reverses a string in Python.").expect("new failed");
    let v_ingress = evaluate(&mut prompt, 2);
    
    if !v_ingress.is_pass() {
        println!("DEBUG: ingress failed. VerbictKind: {:?}, Reason: {:?}", v_ingress.kind, v_ingress.audit.block_reason);
    }
    assert!(v_ingress.is_pass());
    assert_eq!(prompt.matched_intent, Some(MatchedIntent::TaskCodeGeneration));

    // 2. Egress: LLM responds with code block (Allowed)
    let response = "```python\nprint('Hello')\n```";
    let v_egress = evaluate_output(&prompt, response, 2).expect("eval_output failed");

    assert_eq!(v_egress.kind, VerdictKind::Pass);
}

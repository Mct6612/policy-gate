use firewall_core::*;

#[test]
fn test_toml_custom_patterns_and_keywords() {
    // init() loads firewall.toml from the CWD
    init().expect("init failed — make sure firewall.toml is present in crates/firewall-core/");

    // Test that a normal question passes (using QuestionFactual intent)
    let mut input_pass = PromptInput::new("What is the capital of France?").expect("Valid input");
    let res_pass = evaluate(&mut input_pass, 100);
    println!("Pass result: {:?}", res_pass.kind);
    assert!(res_pass.is_pass(), "Standard factual question should pass.");

    // Test custom forbidden keyword/pattern
    // NOTE: In this test environment, we expect it to be blocked.
    let mut input_block = PromptInput::new("this is blocked").expect("Valid input");
    let res_block = evaluate(&mut input_block, 101);
    println!("Block result: {:?}", res_block.kind);
    assert!(matches!(res_block.kind, VerdictKind::Block));
}

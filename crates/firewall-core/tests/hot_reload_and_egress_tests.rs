// hot_reload_and_egress_tests.rs — Tests for SA-077 hot-reload and extended egress
//
// Tests for:
// 1. Dynamic configuration reloading without restart
// 2. Extended PII detection in plain text (medical, biometric, identity docs)
// 3. Structured output scanning (JSON/XML) for sensitive data

use firewall_core::*;

#[test]
fn test_hot_reload_config_snapshot() {
    // Initialize firewall
    let _ = firewall_core::init();
    
    // Get initial config snapshot
    let snapshot1 = firewall_core::get_current_config();
    assert!(snapshot1.is_some());
    
    let snap1 = snapshot1.unwrap();
    assert!(snap1.loaded_at_ns > 0);
    assert!(snap1.file_hash > 0);
}

#[test]
fn test_extended_pii_medical_record() {
    let _ = firewall_core::init();
    
    // Test medical record number detection
    let prompt = PromptInput::new("Patient MRN-12345678 needs review").unwrap();
    let response = "Medical Record MRN-12345678 shows elevated levels";
    
    let verdict = firewall_core::evaluate_output(&prompt, response, 1).unwrap();
    
    // Should detect medical record number in egress
    assert!(!matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
    if let Some(reason) = verdict.egress_reason {
        match reason {
            EgressBlockReason::PiiDetected { pii_type } => {
                assert!(pii_type.contains("Medical") || pii_type.contains("field"));
            }
            _ => panic!("Expected PiiDetected, got {:?}", reason),
        }
    }
}

#[test]
fn test_extended_pii_biometric_fingerprint() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("Verify user identity").unwrap();
    let response = "Fingerprint hash: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
    
    let verdict = firewall_core::evaluate_output(&prompt, response, 2).unwrap();
    
    // Should detect fingerprint hash
    assert!(!matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
}

#[test]
fn test_extended_pii_passport() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("Check document").unwrap();
    let response = "Passport AB1234567 verified";
    
    let verdict = firewall_core::evaluate_output(&prompt, response, 3).unwrap();
    
    // Should detect passport number
    assert!(!matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
}

#[test]
fn test_extended_pii_crypto_wallet() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("Transaction details").unwrap();
    let response = "Bitcoin address: 1A1z7agoat2LWQLZLQ5QHVJQ1N2PWXZW";
    
    let verdict = firewall_core::evaluate_output(&prompt, response, 4).unwrap();
    
    // Should detect crypto wallet address
    assert!(!matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
}

#[test]
fn test_extended_pii_jwt_token() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("Auth token").unwrap();
    let response = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    
    let verdict = firewall_core::evaluate_output(&prompt, response, 5).unwrap();
    
    // Should detect JWT token
    assert!(!matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
}

#[test]
fn test_structured_json_medical_data() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("Patient data").unwrap();
    let json_response = r#"{"patient_id": "MRN-87654321", "name": "John Doe", "status": "active"}"#;
    
    let verdict = firewall_core::evaluate_output(&prompt, json_response, 6).unwrap();
    
    // Should detect medical record in JSON
    assert!(!matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
    if let Some(reason) = verdict.egress_reason {
        match reason {
            EgressBlockReason::PiiDetected { pii_type } => {
                assert!(pii_type.contains("Medical") || pii_type.contains("field"));
            }
            _ => {}
        }
    }
}

#[test]
fn test_structured_json_biometric_data() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("User verification").unwrap();
    let json_response = r#"{"user_id": "alice", "fingerprint": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", "verified": true}"#;
    
    let verdict = firewall_core::evaluate_output(&prompt, json_response, 7).unwrap();
    
    // Should detect fingerprint in JSON
    assert!(!matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
}

#[test]
fn test_structured_xml_passport_data() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("Document verification").unwrap();
    let xml_response = r#"<?xml version="1.0"?><document><passport_number>AB1234567</passport_number><name>Jane Doe</name></document>"#;
    
    let verdict = firewall_core::evaluate_output(&prompt, xml_response, 8).unwrap();
    
    // Should detect passport in XML
    assert!(!matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
}

#[test]
fn test_structured_xml_national_id() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("ID check").unwrap();
    let xml_response = r#"<record><national_id>123456789</national_id><status>verified</status></record>"#;
    
    let verdict = firewall_core::evaluate_output(&prompt, xml_response, 9).unwrap();
    
    // Should detect national ID in XML
    assert!(!matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
}

#[test]
fn test_plain_text_no_pii() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("What is the capital of France?").unwrap();
    let response = "The capital of France is Paris, located in the north-central part of the country.";
    
    let verdict = firewall_core::evaluate_output(&prompt, response, 10).unwrap();
    
    // Should pass — no PII detected
    assert!(matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
}

#[test]
fn test_json_no_pii() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("Get weather").unwrap();
    let json_response = r#"{"city": "Paris", "temperature": 15, "condition": "cloudy"}"#;
    
    let verdict = firewall_core::evaluate_output(&prompt, json_response, 11).unwrap();
    
    // Should pass — no PII in JSON
    assert!(matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
}

#[test]
fn test_xml_no_pii() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("Get data").unwrap();
    let xml_response = r#"<?xml version="1.0"?><response><status>ok</status><message>Success</message></response>"#;
    
    let verdict = firewall_core::evaluate_output(&prompt, xml_response, 12).unwrap();
    
    // Should pass — no PII in XML
    assert!(matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
}

#[test]
fn test_extended_pii_icd10_code() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("Diagnosis").unwrap();
    let response = "ICD-10 code: E11.9 (Type 2 diabetes mellitus without complications)";
    
    let verdict = firewall_core::evaluate_output(&prompt, response, 13).unwrap();
    
    // Should detect ICD-10 code
    assert!(!matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
}

#[test]
fn test_extended_pii_ethereum_address() {
    let _ = firewall_core::init();
    
    let prompt = PromptInput::new("Wallet info").unwrap();
    let response = "Ethereum address: 0x742d35Cc6634C0532925a3b844Bc9e7595f42bE";
    
    let verdict = firewall_core::evaluate_output(&prompt, response, 14).unwrap();
    
    // Should detect Ethereum address
    assert!(!matches!(verdict.kind, VerdictKind::Pass | VerdictKind::DiagnosticAgreement));
}


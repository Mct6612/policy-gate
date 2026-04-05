// egress_structured.rs — Structured Output Scanning (JSON/XML)
//
// SA-077: Detect PII and secrets in structured outputs (JSON/XML).
// Many LLM applications return structured data, and sensitive information
// can hide in field values that would be missed by plain-text scanning.

use regex::Regex;
use std::sync::OnceLock;

/// Result of structured output scanning.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StructuredScanResult {
    /// Type of sensitive data found
    pub data_type: &'static str,
    /// Field name where it was found
    pub field_name: String,
    /// Snippet of the value (truncated for safety)
    #[allow(dead_code)]
    pub value_snippet: String,
}

/// Scan JSON output for PII and secrets.
#[allow(dead_code)]
pub fn scan_json(text: &str) -> Option<StructuredScanResult> {
    // Extract field name — compiled once via OnceLock (outside loop)
    static FIELD_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let field_re = FIELD_RE.get_or_init(|| Regex::new(r#""([^"]+)"\s*:"#).unwrap());

    let patterns = JSON_PII_PATTERNS.get_or_init(|| {
        vec![
            // Medical/Health data
            (
                "MedicalRecordNumber",
                Regex::new(r#"(?i)"(?:medical_record|mrn|patient_id|health_id)"\s*:\s*"[^"]{5,}""#).unwrap(),
            ),
            (
                "DiagnosisCode",
                Regex::new(r#"(?i)"(?:diagnosis|icd_code|icd10)"\s*:\s*"[A-Z]\d{2}(\.\w+)?""#).unwrap(),
            ),
            (
                "Prescription",
                Regex::new(r#"(?i)"(?:prescription|medication|drug_name)"\s*:\s*"[^"]{3,}""#).unwrap(),
            ),
            // Biometric data
            (
                "Fingerprint",
                Regex::new(r#"(?i)"(?:fingerprint|fingerprint_template|fp_hash)"\s*:\s*"[^"]{20,}""#).unwrap(),
            ),
            (
                "FaceEmbedding",
                Regex::new(r#"(?i)"(?:face_embedding|face_vector|facial_features)"\s*:\s*"\[[^\]]{50,}\]""#).unwrap(),
            ),
            (
                "IrisData",
                Regex::new(r#"(?i)"(?:iris_code|iris_template|eye_pattern)"\s*:\s*"[^"]{50,}""#).unwrap(),
            ),
            (
                "VoicePrint",
                Regex::new(r#"(?i)"(?:voice_print|voice_embedding|voice_template)"\s*:\s*"[^"]{50,}""#).unwrap(),
            ),
            // Identity documents
            (
                "PassportNumber",
                Regex::new(r#"(?i)"(?:passport|passport_number|passport_no)"\s*:\s*"[A-Z0-9]{6,12}""#).unwrap(),
            ),
            (
                "DriversLicense",
                Regex::new(r#"(?i)"(?:drivers_license|driver_license|dl_number|license_no)"\s*:\s*"[A-Z0-9]{5,15}""#).unwrap(),
            ),
            (
                "NationalID",
                Regex::new(r#"(?i)"(?:national_id|national_identifier|tax_id|sin|nin)"\s*:\s*"[A-Z0-9]{6,15}""#).unwrap(),
            ),
            // Financial - extended
            (
                "BankAccount",
                Regex::new(r#"(?i)"(?:bank_account|account_number|iban|bic)"\s*:\s*"[A-Z0-9]{8,34}""#).unwrap(),
            ),
            (
                "RoutingNumber",
                Regex::new(r#"(?i)"(?:routing_number|aba|swift_code)"\s*:\s*"[A-Z0-9]{8,11}""#).unwrap(),
            ),
            // Secrets in JSON
            (
                "PrivateKey",
                Regex::new(r#"(?i)"(?:private_key|privatekey|priv_key)"\s*:\s*"[^"]{50,}""#).unwrap(),
            ),
            (
                "DatabaseURL",
                Regex::new(r#"(?i)"(?:database_url|db_url|db_connection_string)"\s*:\s*"[^"]{20,}""#).unwrap(),
            ),
        ]
    });

    for (name, pattern) in patterns {
        if let Some(caps) = pattern.captures(text) {
            let full_match = caps.get(0)?.as_str();
            let field_match = field_re
                .captures(full_match)?
                .get(1)?
                .as_str();
            
            return Some(StructuredScanResult {
                data_type: name,
                field_name: field_match.to_string(),
                value_snippet: truncate_value(full_match, 50),
            });
        }
    }
    None
}

/// Scan XML output for PII and secrets.
#[allow(dead_code)]
pub fn scan_xml(text: &str) -> Option<StructuredScanResult> {
    // Extract tag name — compiled once via OnceLock (outside loop)
    static TAG_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let tag_re = TAG_RE.get_or_init(|| Regex::new(r#"<([^\s>]+)"#).unwrap());

    let patterns = XML_PII_PATTERNS.get_or_init(|| {
        vec![
            // Medical/Health data
            (
                "MedicalRecordNumber",
                Regex::new(r#"(?i)<(?:medical_record|mrn|patient_id|health_id)[^>]*>[^<]{5,}</"#).unwrap(),
            ),
            (
                "DiagnosisCode",
                Regex::new(r#"(?i)<(?:diagnosis|icd_code|icd10)[^>]*>[A-Z]\d{2}(?:\.\w+)?</"#).unwrap(),
            ),
            // Biometric data
            (
                "Fingerprint",
                Regex::new(r#"(?i)<(?:fingerprint|fingerprint_template|fp_hash)[^>]*>[^<]{20,}</"#).unwrap(),
            ),
            (
                "FaceEmbedding",
                Regex::new(r#"(?i)<(?:face_embedding|face_vector|facial_features)[^>]*>[^<]{50,}</"#).unwrap(),
            ),
            // Identity documents
            (
                "PassportNumber",
                Regex::new(r#"(?i)<(?:passport|passport_number|passport_no)[^>]*>[A-Z0-9]{6,12}</"#).unwrap(),
            ),
            (
                "DriversLicense",
                Regex::new(r#"(?i)<(?:drivers_license|driver_license|dl_number)[^>]*>[A-Z0-9]{5,15}</"#).unwrap(),
            ),
            (
                "NationalID",
                Regex::new(r#"(?i)<(?:national_id|national_identifier|tax_id|sin|nin)[^>]*>[A-Z0-9]{6,15}</"#).unwrap(),
            ),
            // Secrets in XML
            (
                "PrivateKey",
                Regex::new(r#"(?i)<(?:private_key|privatekey|priv_key)[^>]*>[^<]{50,}</"#).unwrap(),
            ),
            (
                "APIKey",
                Regex::new(r#"(?i)<(?:api_key|apikey|api_secret)[^>]*>[^<]{16,}</"#).unwrap(),
            ),
        ]
    });

    for (name, pattern) in patterns {
        if let Some(caps) = pattern.captures(text) {
            let full_match = caps.get(0)?.as_str();
            let tag_match = tag_re
                .captures(full_match)?
                .get(1)?
                .as_str();
            
            return Some(StructuredScanResult {
                data_type: name,
                field_name: tag_match.to_string(),
                value_snippet: truncate_value(full_match, 50),
            });
        }
    }
    None
}

/// Detect if text looks like JSON or XML and scan accordingly.
#[allow(dead_code)]
pub fn scan_structured_output(text: &str) -> Option<StructuredScanResult> {
    let trimmed = text.trim();
    
    // Quick detection - JSON starts with { or [
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return scan_json(text);
    }
    
    // XML detection - starts with < (but not just < alone)
    if trimmed.starts_with('<') && trimmed.len() > 2 {
        // Skip XML declaration if present
        let content = if trimmed.starts_with("<?xml") {
            trimmed.find("?>").map(|i| &trimmed[i + 2..]).unwrap_or(trimmed)
        } else {
            trimmed
        };
        
        // Check if it's actually XML (has a tag)
        if content.trim().starts_with('<') && content.contains('>') {
            return scan_xml(text);
        }
    }
    
    None
}

#[allow(dead_code)]
fn truncate_value(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[allow(dead_code)]
static JSON_PII_PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
#[allow(dead_code)]
static XML_PII_PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_json_medical_record() {
        let json = r#"{"patient_id": "MRN-12345678", "name": "John"}"#;
        let result = scan_json(json);
        assert!(result.is_some());
        assert_eq!(result.unwrap().data_type, "MedicalRecordNumber");
    }

    #[test]
    fn test_scan_json_fingerprint() {
        let json = r#"{"user": "alice", "fingerprint": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"}"#;
        let result = scan_json(json);
        assert!(result.is_some());
        assert_eq!(result.unwrap().data_type, "Fingerprint");
    }

    #[test]
    fn test_scan_xml_passport() {
        let xml = r#"<user><passport_number>AB1234567</passport_number></user>"#;
        let result = scan_xml(xml);
        assert!(result.is_some());
        assert_eq!(result.unwrap().data_type, "PassportNumber");
    }

    #[test]
    fn test_scan_structured_auto_detect_json() {
        let json = r#"{"drivers_license": "D1234567"}"#;
        let result = scan_structured_output(json);
        assert!(result.is_some());
        assert_eq!(result.unwrap().data_type, "DriversLicense");
    }

    #[test]
    fn test_scan_structured_auto_detect_xml() {
        let xml = r#"<?xml version="1.0"?><record><national_id>123456789</national_id></record>"#;
        let result = scan_structured_output(xml);
        assert!(result.is_some());
        assert_eq!(result.unwrap().data_type, "NationalID");
    }

    #[test]
    fn test_scan_structured_plain_text() {
        let text = "This is just plain text with no structure";
        let result = scan_structured_output(text);
        assert!(result.is_none());
    }
}
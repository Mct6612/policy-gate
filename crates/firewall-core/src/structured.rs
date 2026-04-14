// structured.rs — Structured input detection and analysis (SA-079)
//
// Detects and analyzes JSON, YAML, and template-based inputs with variable
// substitution patterns. Provides metadata for advisory decisions.
//
// Safety Action SA-079: Structured Input Evaluation
// - Detects JSON/YAML/template formats post-normalisation
// - Scans for variable substitution patterns (${var}, {{var}}, {%var%}, etc.)
// - Identifies sensitive field names (api_key, secret, password, etc.)
// - Non-blocking: detection failure → None, pipeline continues unaffected
//
// NORMALISATION NOTES (SA-029, SA-045):
// PromptInput::new() applies several transformations before this module sees the text:
//   - $ → s  (leet-speak confusable mapping, SA-029: '$' => 's')
//   - _ removed in obfuscation runs (SA-045 separator-strip, only in dense sequences)
//   - All whitespace (including \n) collapsed to single space (SA-045)
//
// Consequences for detection:
//   - "${VAR}" becomes "s{VAR}" — we detect "s{WORD}" as a normalised variable ref
//   - YAML key:value pairs on separate lines become "key: value key2: value2" (one line)
//   - Template dollar-syntax "API: ${KEY}" becomes "API: s{KEY}" — detected via s{

use crate::types::PromptInput;
use std::time::Instant;

/// Maximum time budget for structured input detection (5 ms).
#[allow(dead_code)]
const STRUCTURED_DETECTION_BUDGET_US: u64 = 5_000;

/// Metadata extracted from structured input detection.
#[derive(Debug, Clone)]
#[allow(dead_code)] // SA-079: fields used by advisory/audit consumers; not yet wired to verdict
pub struct StructuredMetadata {
    pub format: StructuredFormat,
    pub field_count: usize,
    pub max_nesting_depth: usize,
    pub has_variable_refs: bool,
    pub variable_patterns: Vec<String>,
    pub sensitive_field_names: Vec<String>,
}

/// Detected format of structured input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum StructuredFormat {
    Json,
    Yaml,
    Template,
}

/// Detect structured input format and extract metadata.
///
/// Returns `Some(StructuredMetadata)` if the input is detected as JSON, YAML,
/// or template-based. Returns `None` for plain text or on watchdog timeout.
#[allow(dead_code)]
pub fn detect_structured_input(input: &PromptInput) -> Option<StructuredMetadata> {
    let start = Instant::now();
    let text = &input.text;

    // JSON first — most common structured format
    if is_likely_json(text) {
        if start.elapsed().as_micros() as u64 > STRUCTURED_DETECTION_BUDGET_US {
            return None;
        }
        return parse_json_structure(text, &start);
    }

    // Template before YAML — template markers contain '{' which would confuse YAML check
    if is_likely_template(text) {
        if start.elapsed().as_micros() as u64 > STRUCTURED_DETECTION_BUDGET_US {
            return None;
        }
        return parse_template_structure(text, &start);
    }

    // YAML last — most heuristic, only if no braces/brackets present
    if is_likely_yaml(text) {
        if start.elapsed().as_micros() as u64 > STRUCTURED_DETECTION_BUDGET_US {
            return None;
        }
        return parse_yaml_structure(text, &start);
    }

    None
}

#[allow(dead_code)]
fn is_likely_json(text: &str) -> bool {
    let trimmed = text.trim();
    (trimmed.starts_with('{') || trimmed.starts_with('['))
        && (trimmed.ends_with('}') || trimmed.ends_with(']'))
        && trimmed.len() > 2
}

#[allow(dead_code)]
fn is_likely_template(text: &str) -> bool {
    // Standard template markers
    if (text.contains("{{") && text.contains("}}"))
        || (text.contains("{%") && text.contains("%}"))
        || (text.contains("<%") && text.contains("%>"))
        || (text.contains("${") && text.contains('}'))
    {
        return true;
    }
    // After SA-029 normalisation: $ → s, so "${VAR}" becomes "s{VAR}".
    // Detect "s{WORD}" where WORD is all-uppercase (typical variable name convention).
    has_normalised_dollar_var(text)
}

/// Returns true if text contains at least one "s{UPPERCASE_WORD}" pattern,
/// which is the post-normalisation form of "${UPPERCASE_VAR}".
#[allow(dead_code)]
fn has_normalised_dollar_var(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b's' && bytes[i + 1] == b'{' {
            // Look for closing brace with at least one uppercase letter inside
            let content_start = i + 2;
            if let Some(rel) = text[content_start..].find('}') {
                let content = &text[content_start..content_start + rel];
                if !content.is_empty()
                    && content
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

#[allow(dead_code)]
fn is_likely_yaml(text: &str) -> bool {
    // No JSON/template markers (including normalised s{ form)
    if text.contains('{') || text.contains('[') {
        return false;
    }
    // Must have at least one "word: " pattern (key: value)
    // After SA-045 whitespace collapse, YAML looks like "key: value key2: value2"
    text.contains(": ")
}

/// Parse JSON structure and extract metadata.
#[allow(dead_code)]
fn parse_json_structure(text: &str, start: &Instant) -> Option<StructuredMetadata> {
    let trimmed = text.trim();
    let mut brace_depth: i32 = 0;
    let mut bracket_depth: i32 = 0;
    let mut in_string = false;
    let mut escape_next = false;
    let mut field_count = 0;
    let mut max_nesting_depth = 0;

    for ch in trimmed.chars() {
        if field_count % 100 == 0
            && start.elapsed().as_micros() as u64 > STRUCTURED_DETECTION_BUDGET_US
        {
            return None;
        }
        if escape_next {
            escape_next = false;
            continue;
        }
        match ch {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '{' if !in_string => {
                brace_depth += 1;
                max_nesting_depth =
                    max_nesting_depth.max((brace_depth + bracket_depth) as usize);
            }
            '}' if !in_string => brace_depth = brace_depth.saturating_sub(1),
            '[' if !in_string => {
                bracket_depth += 1;
                max_nesting_depth =
                    max_nesting_depth.max((brace_depth + bracket_depth) as usize);
            }
            ']' if !in_string => bracket_depth = bracket_depth.saturating_sub(1),
            ':' if !in_string => field_count += 1,
            _ => {}
        }
    }

    if brace_depth != 0 || bracket_depth != 0 {
        return None;
    }

    let mut variable_patterns = Vec::new();
    let mut sensitive_field_names = Vec::new();
    scan_for_variables_and_fields(trimmed, &mut variable_patterns, &mut sensitive_field_names);
    let has_variable_refs = !variable_patterns.is_empty();

    Some(StructuredMetadata {
        format: StructuredFormat::Json,
        field_count,
        max_nesting_depth,
        has_variable_refs,
        variable_patterns,
        sensitive_field_names,
    })
}

/// Parse template structure and extract variable patterns.
#[allow(dead_code)]
fn parse_template_structure(text: &str, start: &Instant) -> Option<StructuredMetadata> {
    let mut variable_patterns = Vec::new();
    let mut sensitive_field_names = Vec::new();

    // Standard open/close pairs
    let pairs: &[(&str, &str)] = &[
        ("{{", "}}"),
        ("{%", "%}"),
        ("<%", "%>"),
        ("${", "}"),
    ];

    for &(open, close) in pairs {
        let mut pos = 0;
        while pos < text.len() {
            if start.elapsed().as_micros() as u64 > STRUCTURED_DETECTION_BUDGET_US {
                return None;
            }
            match text[pos..].find(open) {
                None => break,
                Some(rel) => {
                    let abs_open = pos + rel;
                    let content_start = abs_open + open.len();
                    match text[content_start..].find(close) {
                        None => break,
                        Some(rel_close) => {
                            let content_end = content_start + rel_close;
                            let content = &text[content_start..content_end];
                            if let Some(var_name) = content.split_whitespace().next() {
                                let pattern = format!("{}{}{}", open, var_name, close);
                                variable_patterns.push(pattern);
                                if is_sensitive_field_name(var_name) {
                                    sensitive_field_names.push(var_name.to_string());
                                }
                            }
                            pos = content_end + close.len();
                        }
                    }
                }
            }
        }
    }

    // Also scan for normalised dollar-vars: s{UPPERCASE_WORD}
    scan_normalised_dollar_vars(text, &mut variable_patterns, &mut sensitive_field_names);

    if variable_patterns.is_empty() {
        return None;
    }

    Some(StructuredMetadata {
        format: StructuredFormat::Template,
        field_count: variable_patterns.len(),
        max_nesting_depth: 1,
        has_variable_refs: true,
        variable_patterns,
        sensitive_field_names,
    })
}

/// Scan for normalised dollar-variable patterns: s{UPPERCASE_WORD}
/// These are the post-SA-029 form of ${UPPERCASE_VAR}.
#[allow(dead_code)]
fn scan_normalised_dollar_vars(
    text: &str,
    variable_patterns: &mut Vec<String>,
    sensitive_field_names: &mut Vec<String>,
) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b's' && bytes[i + 1] == b'{' {
            let content_start = i + 2;
            if let Some(rel) = text[content_start..].find('}') {
                let content = &text[content_start..content_start + rel];
                if !content.is_empty()
                    && content
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                {
                    let pattern = format!("s{{{}}}", content);
                    variable_patterns.push(pattern);
                    if is_sensitive_field_name(content) {
                        sensitive_field_names.push(content.to_string());
                    }
                    i = content_start + rel + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
}

/// Parse YAML structure.
///
/// After SA-045 whitespace collapse, YAML input looks like a single line:
/// "key: value key2: value2 key3: value3"
/// We walk all occurrences of ": " to extract key-value pairs.
#[allow(dead_code)]
fn parse_yaml_structure(text: &str, start: &Instant) -> Option<StructuredMetadata> {
    let mut field_count = 0;
    let mut variable_patterns = Vec::new();
    let mut sensitive_field_names = Vec::new();

    let mut search_pos = 0;
    while let Some(rel) = text[search_pos..].find(": ") {
        if start.elapsed().as_micros() as u64 > STRUCTURED_DETECTION_BUDGET_US {
            return None;
        }

        let colon_pos = search_pos + rel;

        // Key = last whitespace-delimited token before ": "
        let before = &text[..colon_pos];
        let key = before.split_whitespace().next_back().unwrap_or("").trim();

        if !key.is_empty() && !key.starts_with('#') {
            field_count += 1;
            if is_sensitive_field_name(key) {
                sensitive_field_names.push(key.to_string());
            }
        }

        // Value portion: from after ": " to start of next key
        let after_colon = colon_pos + 2;
        let value_end = text[after_colon..]
            .find(": ")
            .map(|r| {
                let next_colon = after_colon + r;
                let segment = &text[after_colon..next_colon];
                after_colon
                    + segment
                        .rfind(char::is_whitespace)
                        .map(|p| p + 1)
                        .unwrap_or(0)
            })
            .unwrap_or(text.len());

        let value = &text[after_colon..value_end];
        if let Some(var) = extract_variable_pattern(value) {
            variable_patterns.push(var);
        }

        search_pos = colon_pos + 2;
    }

    if field_count == 0 {
        return None;
    }

    Some(StructuredMetadata {
        format: StructuredFormat::Yaml,
        field_count,
        max_nesting_depth: 0,
        has_variable_refs: !variable_patterns.is_empty(),
        variable_patterns,
        sensitive_field_names,
    })
}

/// Scan JSON text for quoted field names (sensitive detection) and variable patterns.
#[allow(dead_code)]
fn scan_for_variables_and_fields(
    text: &str,
    variable_patterns: &mut Vec<String>,
    sensitive_field_names: &mut Vec<String>,
) {
    // Extract quoted string tokens → sensitive field name check
    let mut in_string = false;
    let mut escape_next = false;
    let mut current_token = String::new();

    for ch in text.chars() {
        if escape_next {
            escape_next = false;
            if in_string {
                current_token.push(ch);
            }
            continue;
        }
        match ch {
            '\\' if in_string => escape_next = true,
            '"' => {
                if in_string && is_sensitive_field_name(&current_token) {
                    sensitive_field_names.push(current_token.clone());
                }
                if in_string {
                    current_token.clear();
                }
                in_string = !in_string;
            }
            _ if in_string => current_token.push(ch),
            _ => {}
        }
    }

    // Scan for standard variable patterns
    let pairs: &[(&str, &str)] = &[
        ("${", "}"),
        ("{{", "}}"),
        ("{%", "%}"),
        ("<%", "%>"),
    ];
    for &(open, close) in pairs {
        let mut pos = 0;
        while let Some(rel) = text[pos..].find(open) {
            let abs = pos + rel;
            let content_start = abs + open.len();
            match text[content_start..].find(close) {
                None => break,
                Some(rel_close) => {
                    let content_end = content_start + rel_close;
                    let pattern = text[abs..content_end + close.len()].to_string();
                    variable_patterns.push(pattern);
                    pos = content_end + close.len();
                }
            }
        }
    }

    // Also scan for normalised dollar-vars: s{UPPERCASE_WORD}
    scan_normalised_dollar_vars(text, variable_patterns, sensitive_field_names);
}

/// Extract the first variable pattern found in a text fragment.
#[allow(dead_code)]
fn extract_variable_pattern(text: &str) -> Option<String> {
    let pairs: &[(&str, &str)] = &[
        ("${", "}"),
        ("{{", "}}"),
        ("{%", "%}"),
        ("<%", "%>"),
    ];
    for &(open, close) in pairs {
        if let Some(start_idx) = text.find(open) {
            let content_start = start_idx + open.len();
            if let Some(rel_close) = text[content_start..].find(close) {
                let end = content_start + rel_close + close.len();
                return Some(text[start_idx..end].to_string());
            }
        }
    }
    None
}

/// Returns true if the field name suggests sensitive data.
#[allow(dead_code)]
fn is_sensitive_field_name(field: &str) -> bool {
    let lower = field.to_lowercase();
    const SENSITIVE: &[&str] = &[
        "api_key", "apikey", "api-key",
        "secret",
        "password", "passwd", "pwd",
        "token",
        "auth",
        "credential",
        "private_key", "privatekey", "private-key",
        "access_key", "accesskey", "access-key",
        "aws_key", "awskey", "aws-key",
        "db_password", "dbpassword", "db-password",
        "ssh_key", "sshkey", "ssh-key",
        "oauth", "bearer", "jwt",
        "session", "cookie", "hmac", "signature",
    ];
    SENSITIVE.iter().any(|kw| lower.contains(kw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(text: &str) -> PromptInput {
        PromptInput::new(text).expect("PromptInput::new failed")
    }

    #[test]
    fn json_detection_simple_object() {
        let input = make_input(r#"{"name": "Alice", "age": 30}"#);
        let metadata = detect_structured_input(&input);
        assert!(metadata.is_some());
        let m = metadata.expect("metadata should be present in test");
        assert_eq!(m.format, StructuredFormat::Json);
        assert_eq!(m.field_count, 2);
    }

    #[test]
    fn json_detection_with_variable_refs() {
        // SA-029: $ → s, so "${API_KEY}" normalises to "s{APIKEY}" (underscore may be
        // stripped by SA-045 separator-strip if in an obfuscation run).
        // We detect s{UPPERCASE} as a normalised variable reference.
        let input = make_input(r#"{"api_key": "${API_KEY}", "secret": "${SECRET}"}"#);
        let metadata = detect_structured_input(&input);
        assert!(metadata.is_some());
        let m = metadata.expect("metadata should be present in test");
        assert!(!m.sensitive_field_names.is_empty(), "api_key and secret should be detected");
        assert!(m.has_variable_refs, "s{{...}} patterns should be detected as variable refs");
        assert_eq!(m.variable_patterns.len(), 2);
    }

    #[test]
    fn template_detection_jinja2() {
        let input = make_input("Hello {{ name }}, your token is {{ token }}");
        let metadata = detect_structured_input(&input);
        assert!(metadata.is_some());
        let m = metadata.expect("metadata should be present in test");
        assert_eq!(m.format, StructuredFormat::Template);
        assert!(m.has_variable_refs);
        assert_eq!(m.variable_patterns.len(), 2);
    }

    #[test]
    fn template_detection_dollar_syntax() {
        // SA-029: $ → s, so "${API_URL}" → "s{APIURL}".
        // is_likely_template detects "s{UPPERCASE}" via has_normalised_dollar_var().
        let input = make_input("API endpoint: ${API_URL}, key: ${API_KEY}");
        let metadata = detect_structured_input(&input);
        assert!(metadata.is_some(), "normalised s{{...}} should be detected as template");
        let m = metadata.expect("metadata should be present in test");
        assert_eq!(m.format, StructuredFormat::Template);
        assert!(m.has_variable_refs);
    }

    #[test]
    fn yaml_detection_simple() {
        // SA-045: \n → space, so "name: Alice\nage: 30\nemail: x" becomes
        // "name: Alice age: 30 email: x" — 3 ": " occurrences → field_count = 3.
        let input = make_input("name: Alice\nage: 30\nemail: alice@example.com");
        let metadata = detect_structured_input(&input);
        assert!(metadata.is_some());
        let m = metadata.expect("metadata should be present in test");
        assert_eq!(m.format, StructuredFormat::Yaml);
        assert_eq!(m.field_count, 3);
    }

    #[test]
    fn yaml_detection_with_sensitive_fields() {
        let input = make_input("username: alice\napi_key: secret123\npassword: pass456");
        let metadata = detect_structured_input(&input);
        assert!(metadata.is_some());
        let m = metadata.expect("metadata should be present in test");
        assert!(!m.sensitive_field_names.is_empty());
    }

    #[test]
    fn plain_text_no_detection() {
        let input = make_input("This is just plain text without any structure");
        let metadata = detect_structured_input(&input);
        assert!(metadata.is_none());
    }

    #[test]
    fn json_with_nesting() {
        let input = make_input(r#"{"user": {"name": "Alice", "profile": {"age": 30}}}"#);
        let metadata = detect_structured_input(&input);
        assert!(metadata.is_some());
        let m = metadata.expect("metadata should be present in test");
        assert!(m.max_nesting_depth > 1);
    }

    #[test]
    fn sensitive_field_detection() {
        let input = make_input(r#"{"username": "alice", "api_key": "secret", "password": "pass"}"#);
        let metadata = detect_structured_input(&input);
        assert!(metadata.is_some());
        let m = metadata.expect("metadata should be present in test");
        assert!(m.sensitive_field_names.contains(&"api_key".to_string()));
        assert!(m.sensitive_field_names.contains(&"password".to_string()));
    }

    #[test]
    fn unbalanced_json_rejected() {
        let input = make_input(r#"{"name": "Alice", "age": 30"#);
        let metadata = detect_structured_input(&input);
        assert!(metadata.is_none());
    }
}

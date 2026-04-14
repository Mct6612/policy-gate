use crate::types::AuditEntry;
use std::sync::OnceLock;

static HMAC_KEY: OnceLock<[u8; 32]> = OnceLock::new();
static LAST_AUDIT_HMAC: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
static HMAC_KEY_PATH: &str = "audit_hmac_key.seal";
static CHAIN_SEAL_PATH: &str = "audit_chain.seal";

pub(crate) fn init_audit() -> Result<(), String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if HMAC_KEY.get().is_none() {
            let key = load_or_generate_hmac_key()?;
            HMAC_KEY
                .set(key)
                .map_err(|_| "audit HMAC key was already initialised".to_string())?;
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        if HMAC_KEY.get().is_none() {
            return Err(
                "WASM audit HMAC key is not set. Call set_wasm_hmac_key() before init().".into(),
            );
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        if let Ok(seal_content) = std::fs::read_to_string(CHAIN_SEAL_PATH) {
            let trimmed = seal_content.trim();
            if !trimmed.is_empty() && trimmed.len() == 64 {
                // SA-085: Handle poisoned mutex gracefully - clear poison and recover
                let mut guard = match LAST_AUDIT_HMAC.lock() {
                    Ok(g) => g,
                    Err(poisoned) => {
                        eprintln!("[audit] Mutex poisoned, recovering: {}", poisoned);
                        poisoned.into_inner()
                    }
                };
                *guard = Some(trimmed.to_string());
            }
        }
    }

    Ok(())
}

pub(crate) fn attach_chain_hmac(entry: &mut AuditEntry) {
    if let Some(key) = HMAC_KEY.get() {
        let mut last_hmac_guard = match LAST_AUDIT_HMAC.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        
        let prev_hmac = last_hmac_guard.clone();
        let current_hmac = compute_audit_hmac(key, entry, prev_hmac.as_deref());
        entry.chain_hmac = Some(current_hmac.clone());
        *last_hmac_guard = Some(current_hmac.clone());
        
        #[cfg(not(target_arch = "wasm32"))]
        if let Err(e) = std::fs::write(CHAIN_SEAL_PATH, &current_hmac) {
            eprintln!("[audit] Warning: Could not persist chain seal: {}", e);
        }
    } else {
        eprintln!("[audit] ERROR: attach_chain_hmac called before audit key initialisation");
    }
}

pub(crate) fn compute_audit_hmac(
    key: &[u8; 32],
    entry: &AuditEntry,
    prev_hmac: Option<&str>,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key size incorrect");
    mac.update(&entry.sequence.to_le_bytes());
    mac.update(&entry.ingested_at_ns.to_le_bytes());
    mac.update(&entry.decided_at_ns.to_le_bytes());
    mac.update(entry.input_hash.as_bytes());
    if let Some(prev) = prev_hmac {
        mac.update(prev.as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
pub(crate) fn hmac_key() -> Option<&'static [u8; 32]> {
    HMAC_KEY.get()
}

#[cfg(not(feature = "fips"))]
pub(crate) fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(feature = "fips")]
pub(crate) fn sha256_hex(input: &str) -> String {
    use aws_lc_rs::digest;
    let digest = digest::digest(&digest::SHA256, input.as_bytes());
    hex::encode(digest.as_ref())
}

#[cfg(not(target_arch = "wasm32"))]
fn load_or_generate_hmac_key() -> Result<[u8; 32], String> {
    if let Ok(key_str) = std::env::var("POLICY_GATE_HMAC_KEY") {
        return parse_hmac_key_hex(&key_str);
    }

    if let Ok(sealed_key) = std::fs::read_to_string(HMAC_KEY_PATH) {
        return parse_hmac_key_hex(sealed_key.trim());
    }

    use getrandom::getrandom;
    let mut key = [0u8; 32];
    getrandom(&mut key).map_err(|e| {
        format!(
            "could not generate audit HMAC key via getrandom: {}. Refusing to start without audit integrity.",
            e
        )
    })?;

    std::fs::write(HMAC_KEY_PATH, hex::encode(key)).map_err(|e| {
        format!(
            "could not persist audit HMAC key to {}: {}",
            HMAC_KEY_PATH, e
        )
    })?;

    Ok(key)
}

fn parse_hmac_key_hex(input: &str) -> Result<[u8; 32], String> {
    let key_bytes = hex::decode(input)
        .map_err(|e| format!("invalid POLICY_GATE_HMAC_KEY / sealed HMAC key hex: {}", e))?;
    if key_bytes.len() != 32 {
        return Err(format!(
            "invalid HMAC key length: expected 32 bytes, got {} bytes",
            key_bytes.len()
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

#[cfg(target_arch = "wasm32")]
pub fn set_wasm_hmac_key(key_hex: &str) -> Result<(), String> {
    let key = parse_hmac_key_hex(key_hex)?;
    HMAC_KEY
        .set(key)
        .map_err(|_| "WASM audit HMAC key is already initialised".to_string())
}

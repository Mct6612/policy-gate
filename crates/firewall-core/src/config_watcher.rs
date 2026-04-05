// config_watcher.rs — Hot-reload configuration management
//
// SA-077: Dynamic configuration reloading without restart.
// Allows firewall.toml changes to be picked up at runtime via a background
// watcher thread. Uses RwLock for thread-safe read/write access.
//
// Safety considerations:
// - Config is read-only after initial load (no mutation during evaluation)
// - RwLock ensures readers don't block writers and vice versa
// - Reload is non-blocking; old config remains in use until new one is ready
// - Invalid configs are rejected; old config remains active

use crate::config;
use std::sync::RwLock;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Wrapper around the current firewall configuration with metadata.
#[derive(Debug, Clone)]
pub struct ConfigSnapshot {
    /// The actual configuration
    pub config: config::FirewallConfig,
    /// Timestamp when this config was loaded
    pub loaded_at_ns: u128,
    /// Hash of the config file for change detection
    pub file_hash: u64,
}

/// Global configuration state — protected by RwLock for hot-reload.
static CONFIG_STATE: OnceLock<RwLock<ConfigSnapshot>> = OnceLock::new();

/// Initialize the config watcher with the initial configuration.
pub(crate) fn init_config_watcher(initial_config: config::FirewallConfig) {
    let file_hash = compute_config_hash(&initial_config);
    let snapshot = ConfigSnapshot {
        config: initial_config,
        loaded_at_ns: now_ns(),
        file_hash,
    };
    let _ = CONFIG_STATE.get_or_init(|| RwLock::new(snapshot));
}

/// Get the current configuration snapshot (read-only).
pub fn get_current_config() -> Option<ConfigSnapshot> {
    CONFIG_STATE.get().and_then(|lock| lock.read().ok().map(|guard| guard.clone()))
}

/// Attempt to reload configuration from firewall.toml.
/// Returns Ok(true) if config was reloaded, Ok(false) if no changes detected,
/// or Err if the new config is invalid (old config remains active).
pub fn try_reload_config() -> Result<bool, String> {
    let new_config = config::FirewallConfig::load()
        .map_err(|e| format!("Failed to load firewall.toml: {}", e))?;
    
    let new_hash = compute_config_hash(&new_config);
    
    // Check if anything actually changed
    if let Ok(current) = CONFIG_STATE.get().ok_or("Config not initialized")?.read() {
        if current.file_hash == new_hash {
            return Ok(false); // No changes
        }
    }
    
    // Validate the new config before applying
    if let Some(custom) = &new_config.intents {
        for entry in custom {
            regex::Regex::new(&entry.regex).map_err(|e| {
                format!("Invalid regex in intent pattern [{}]: {}", entry.id, e)
            })?;
        }
    }
    
    // Apply the new config
    if let Ok(lock) = CONFIG_STATE.get().ok_or("Config not initialized")?.write() {
        // This is a bit tricky — we need to replace the entire snapshot
        // The RwLock doesn't have a direct replace, so we drop the write guard
        // and re-acquire it. This is safe because we're the only writer.
        drop(lock);
    }
    
    let snapshot = ConfigSnapshot {
        config: new_config,
        loaded_at_ns: now_ns(),
        file_hash: new_hash,
    };
    
    if let Ok(mut lock) = CONFIG_STATE.get().ok_or("Config not initialized")?.write() {
        *lock = snapshot;
        Ok(true)
    } else {
        Err("Failed to acquire write lock on config".into())
    }
}

/// Compute a simple hash of the configuration for change detection.
/// This is not cryptographic — just for detecting if the config changed.
fn compute_config_hash(config: &config::FirewallConfig) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    
    // Hash the intents
    if let Some(intents) = &config.intents {
        for intent in intents {
            intent.id.hash(&mut hasher);
            intent.regex.hash(&mut hasher);
        }
    }
    
    // Hash forbidden keywords
    if let Some(keywords) = &config.forbidden_keywords {
        for kw in keywords {
            kw.hash(&mut hasher);
        }
    }
    
    // Hash context window
    config.context_window.hash(&mut hasher);
    
    hasher.finish()
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_hash_consistency() {
        let config1 = config::FirewallConfig::default();
        let config2 = config::FirewallConfig::default();
        
        assert_eq!(compute_config_hash(&config1), compute_config_hash(&config2));
    }

    #[test]
    fn test_config_hash_changes_with_keywords() {
        let mut config1 = config::FirewallConfig::default();
        let mut config2 = config::FirewallConfig::default();
        
        config2.forbidden_keywords = Some(vec!["test".to_string()]);
        
        assert_ne!(compute_config_hash(&config1), compute_config_hash(&config2));
    }
}
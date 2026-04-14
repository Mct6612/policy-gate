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

/// Map of Tenant IDs to their last-known file hashes for hot-reload change detection.
static TENANT_FILE_HASHES: OnceLock<RwLock<std::collections::HashMap<String, u64>>> = OnceLock::new();

/// Initialize the config watcher with the initial configuration.
pub(crate) fn init_config_watcher(initial_config: config::FirewallConfig) {
    let file_hash = compute_config_hash(&initial_config);
    let snapshot = ConfigSnapshot {
        config: initial_config,
        loaded_at_ns: now_ns(),
        file_hash,
    };
    let _ = CONFIG_STATE.get_or_init(|| RwLock::new(snapshot));

    // SA-077: Background thread to poll for config changes.
    // Interval: 2 seconds.
    std::thread::spawn(|| {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if let Err(e) = try_reload_config() {
                eprintln!("[SA-077] Hot-reload failed: {}", e);
            }
        }
    });
}

/// Get the current configuration snapshot (read-only).
pub fn get_current_config() -> Option<ConfigSnapshot> {
    CONFIG_STATE.get().and_then(|lock| lock.read().ok().map(|guard| guard.clone()))
}

/// Attempt to reload configuration from firewall.toml.
/// Returns Ok(true) if config was reloaded, Ok(false) if no changes detected,
/// or Err if the new config is invalid (old config remains active).
pub fn try_reload_config() -> Result<bool, String> {
    let mut new_config = config::FirewallConfig::load()
        .map_err(|e| format!("Failed to load firewall.toml: {}", e))?;
    
    // Apply defaults (e.g. allow_anonymous_tenants = true for legacy default config)
    crate::init::apply_defaults(&mut new_config, None);

    let new_hash = compute_config_hash(&new_config);
    
    // Check if anything actually changed
    if let Ok(current) = CONFIG_STATE.get().ok_or("Config not initialized")?.read() {
        if current.file_hash == new_hash {
            return Ok(false); // No changes
        }
    }
    
    // Validate the new config before applying
    if let Err(errors) = new_config.validate() {
        return Err(format!("Staged validation failed: {}", errors.join("; ")));
    }
    
    let snapshot = ConfigSnapshot {
        config: new_config.clone(),
        loaded_at_ns: now_ns(),
        file_hash: new_hash,
    };
    
    if let Ok(mut lock) = CONFIG_STATE.get().ok_or("Config not initialized")?.write() {
        *lock = snapshot;
        // Update the 'default' tenant in the registry as well
        if let Some(registry_lock) = crate::init::get_tenant_registry() {
            if let Ok(mut reg) = registry_lock.write() {
                reg.insert("default".into(), new_config);
            }
        }
        // SA-048: Dynamic patterns are updated via the config snapshot, but 
        // the evaluation cache contains decisions based on the old policy.
        crate::clear_eval_cache();
        Ok(true)
    } else {
        Err("Failed to acquire write lock on config".into())
    }
}

/// Attempt to reload all tenant configurations from a directory.
/// Returns Ok(true) if at least one tenant was reloaded.
#[cfg(not(target_arch = "wasm32"))]
pub fn reload_tenant_directory<P: AsRef<std::path::Path>>(dir_path: P) -> Result<bool, String> {
    let dir = dir_path.as_ref();
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }

    let mut changed = false;
    let hash_map_lock = TENANT_FILE_HASHES.get_or_init(|| RwLock::new(std::collections::HashMap::new()));
    let registry_lock = crate::init::get_tenant_registry()
        .ok_or("Tenant registry not initialized")?;

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                if let Ok(cfg) = config::FirewallConfig::load_from_path(&path) {
                    let tenant_id = cfg.tenant_id.clone()
                        .or_else(|| {
                            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                            if stem == "firewall" {
                                Some("default".into())
                            } else {
                                Some(stem.to_string())
                            }
                        })
                        .unwrap_or_else(|| "default".into());
                    
                    let new_hash = compute_config_hash(&cfg);
                    
                    let should_reload = if let Ok(hashes) = hash_map_lock.read() {
                        hashes.get(&tenant_id).copied() != Some(new_hash)
                    } else {
                        true
                    };

                    if should_reload {
                        let mut cfg_mut = cfg;
                        crate::init::apply_defaults(&mut cfg_mut, None);
                        if cfg_mut.validate().is_ok() {
                            if let Ok(mut reg) = registry_lock.write() {
                                reg.insert(tenant_id.clone(), cfg_mut);
                                if let Ok(mut hashes) = hash_map_lock.write() {
                                    hashes.insert(tenant_id, new_hash);
                                }
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
    }

    if changed {
        crate::clear_eval_cache();
    }
    Ok(changed)
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
    
    // Hash rule exceptions
    if let Some(exceptions) = &config.rule_exceptions {
        for exc in exceptions {
            exc.rule_id.hash(&mut hasher);
            exc.regex.hash(&mut hasher);
            exc.reason.hash(&mut hasher);
        }
    }

    // Hash tenant policy settings (SA-077: critical for anonymous access)
    config.allow_anonymous_tenants.hash(&mut hasher);
    config.shadow_mode.hash(&mut hasher);
    config.audit_detail_level.map(|l| format!("{:?}", l).to_string()).hash(&mut hasher);
    config.semantic_threshold.map(|f| (f * 1000.0) as i64).hash(&mut hasher);
    config.semantic_enforce_threshold.map(|f| (f * 1000.0) as i64).hash(&mut hasher);

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
        let config1 = config::FirewallConfig::default();
        let mut config2 = config::FirewallConfig::default();

        config2.forbidden_keywords = Some(vec!["test".to_string()]);

        assert_ne!(compute_config_hash(&config1), compute_config_hash(&config2));
    }
}
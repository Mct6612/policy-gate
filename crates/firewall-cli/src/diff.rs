use colored::*;
use firewall_core::config::FirewallConfig;
use std::collections::{HashMap, HashSet};

pub fn display_diff(old: &FirewallConfig, new: &FirewallConfig) {
    println!("{}", "--- Policy Comparison ---".bold());

    // 1. Compare Intents
    println!("\n{}", "Intents:".underline());
    let old_intents: HashMap<String, &firewall_core::config::IntentEntry> = old
        .intents
        .as_ref()
        .map(|v| v.iter().map(|i| (i.id.clone(), i)).collect())
        .unwrap_or_default();

    let new_intents: HashMap<String, &firewall_core::config::IntentEntry> = new
        .intents
        .as_ref()
        .map(|v| v.iter().map(|i| (i.id.clone(), i)).collect())
        .unwrap_or_default();

    let all_ids: HashSet<String> = old_intents
        .keys()
        .cloned()
        .chain(new_intents.keys().cloned())
        .collect();
    let mut ids_sorted: Vec<_> = all_ids.into_iter().collect();
    ids_sorted.sort();

    let mut changed_count = 0;
    for id in ids_sorted {
        match (old_intents.get(&id), new_intents.get(&id)) {
            (None, Some(n)) => {
                println!(
                    "{} [{}] ({:?}) -> {}",
                    "+".green(),
                    n.id.green(),
                    n.intent,
                    n.regex
                );
                changed_count += 1;
            }
            (Some(o), None) => {
                println!("{} [{}]", "-".red(), o.id.red());
                changed_count += 1;
            }
            (Some(o), Some(n)) => {
                if o.regex != n.regex || o.intent != n.intent {
                    println!("{} [{}]", "M".yellow(), id.yellow());
                    if o.intent != n.intent {
                        println!("  Intent: {:?} -> {:?}", o.intent, n.intent);
                    }
                    if o.regex != n.regex {
                        println!("  Regex:  {}", o.regex.red());
                        println!("          {}", n.regex.green());
                    }
                    changed_count += 1;
                }
            }
            (None, None) => unreachable!(),
        }
    }
    if changed_count == 0 {
        println!("  (No changes to intents)");
    }

    // 2. Compare Forbidden Keywords
    println!("\n{}", "Forbidden Keywords:".underline());
    let old_kws: HashSet<String> = old
        .forbidden_keywords
        .as_ref()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let new_kws: HashSet<String> = new
        .forbidden_keywords
        .as_ref()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect();

    let added_kws: Vec<_> = new_kws.difference(&old_kws).collect();
    let removed_kws: Vec<_> = old_kws.difference(&new_kws).collect();

    if added_kws.is_empty() && removed_kws.is_empty() {
        println!("  (No changes to keywords)");
    } else {
        for kw in added_kws {
            println!("{} {}", "+".green(), kw.green());
        }
        for kw in removed_kws {
            println!("{} {}", "-".red(), kw.red());
        }
    }

    // 3. Compare Context Window
    if old.context_window != new.context_window {
        println!(
            "\n{}: {:?} -> {:?}",
            "Context Window".yellow(),
            old.context_window,
            new.context_window
        );
    }

    // 4. Compare Rule Exceptions (Pillar 5)
    println!("\n{}", "Rule Exceptions:".underline());
    let old_exceptions: HashMap<String, &firewall_core::config::RuleExceptionEntry> = old
        .rule_exceptions
        .as_ref()
        .map(|v| {
            v.iter()
                .map(|e| (format!("{}:{}", e.rule_id, e.regex), e))
                .collect()
        })
        .unwrap_or_default();

    let new_exceptions: HashMap<String, &firewall_core::config::RuleExceptionEntry> = new
        .rule_exceptions
        .as_ref()
        .map(|v| {
            v.iter()
                .map(|e| (format!("{}:{}", e.rule_id, e.regex), e))
                .collect()
        })
        .unwrap_or_default();

    let all_exc_ids: HashSet<String> = old_exceptions
        .keys()
        .cloned()
        .chain(new_exceptions.keys().cloned())
        .collect();
    let mut exc_ids_sorted: Vec<_> = all_exc_ids.into_iter().collect();
    exc_ids_sorted.sort();

    let mut exc_changed = 0;
    for id in exc_ids_sorted {
        match (old_exceptions.get(&id), new_exceptions.get(&id)) {
            (None, Some(n)) => {
                println!(
                    "{} [{}] {} -> {}",
                    "+".green(),
                    n.rule_id.green(),
                    n.regex,
                    n.reason
                );
                exc_changed += 1;
            }
            (Some(o), None) => {
                println!(
                    "{} [{}] {} -> {}",
                    "-".red(),
                    o.rule_id.red(),
                    o.regex,
                    o.reason
                );
                exc_changed += 1;
            }
            (Some(o), Some(n)) => {
                if o.reason != n.reason {
                    println!(
                        "  {} [{}] {}: {} -> {}",
                        "~".yellow(),
                        id.yellow(),
                        o.regex,
                        o.reason.red(),
                        n.reason.green()
                    );
                    exc_changed += 1;
                }
            }
            (None, None) => unreachable!(),
        }
    }
    if exc_changed == 0 {
        println!("  (No changes to rule exceptions)");
    }

    // 5. Compare Tenant & Policy Settings (Pillar 5)
    println!("\n{}", "Policy Settings:".underline());
    let mut policy_changed = false;

    if old.allow_anonymous_tenants != new.allow_anonymous_tenants {
        println!(
            "  {}: {:?} -> {:?}",
            "Allow Anonymous Tenants".yellow(),
            old.allow_anonymous_tenants,
            new.allow_anonymous_tenants
        );
        policy_changed = true;
    }

    if old.shadow_mode != new.shadow_mode {
        println!(
            "  {}: {:?} -> {:?}",
            "Shadow Mode".yellow(),
            old.shadow_mode,
            new.shadow_mode
        );
        policy_changed = true;
    }

    if old.audit_detail_level != new.audit_detail_level {
        println!(
            "  {}: {:?} -> {:?}",
            "Audit Detail Level".yellow(),
            old.audit_detail_level,
            new.audit_detail_level
        );
        policy_changed = true;
    }

    if old.semantic_threshold != new.semantic_threshold {
        println!(
            "  {}: {:?} -> {:?}",
            "Semantic Threshold".yellow(),
            old.semantic_threshold,
            new.semantic_threshold
        );
        policy_changed = true;
    }

    if old.semantic_enforce_threshold != new.semantic_enforce_threshold {
        println!(
            "  {}: {:?} -> {:?}",
            "Semantic Enforce Threshold".yellow(),
            old.semantic_enforce_threshold,
            new.semantic_enforce_threshold
        );
        policy_changed = true;
    }

    if let (Some(old_tid), Some(new_tid)) = (&old.tenant_id, &new.tenant_id) {
        if old_tid != new_tid {
            println!("  {}: {} -> {}", "Tenant ID".yellow(), old_tid, new_tid);
            policy_changed = true;
        }
    } else if old.tenant_id != new.tenant_id {
        println!(
            "  {}: {:?} -> {:?}",
            "Tenant ID".yellow(),
            old.tenant_id,
            new.tenant_id
        );
        policy_changed = true;
    }

    if !policy_changed {
        println!("  (No changes to policy settings)");
    }

    println!("\n{}", "--- End Diff ---".bold());
}

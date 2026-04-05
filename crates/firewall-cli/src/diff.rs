use firewall_core::config::FirewallConfig;
use colored::*;
use std::collections::{HashMap, HashSet};

pub fn display_diff(old: &FirewallConfig, new: &FirewallConfig) {
    println!("{}", "--- Policy Comparison ---".bold());

    // 1. Compare Intents
    println!("\n{}", "Intents:".underline());
    let old_intents: HashMap<String, &firewall_core::config::IntentEntry> = old.intents.as_ref()
        .map(|v| v.iter().map(|i| (i.id.clone(), i)).collect())
        .unwrap_or_default();
    
    let new_intents: HashMap<String, &firewall_core::config::IntentEntry> = new.intents.as_ref()
        .map(|v| v.iter().map(|i| (i.id.clone(), i)).collect())
        .unwrap_or_default();

    let all_ids: HashSet<String> = old_intents.keys().cloned().chain(new_intents.keys().cloned()).collect();
    let mut ids_sorted: Vec<_> = all_ids.into_iter().collect();
    ids_sorted.sort();

    let mut changed_count = 0;
    for id in ids_sorted {
        match (old_intents.get(&id), new_intents.get(&id)) {
            (None, Some(n)) => {
                println!("{} [{}] ({:?}) -> {}", "+".green(), n.id.green(), n.intent, n.regex);
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
    let old_kws: HashSet<String> = old.forbidden_keywords.as_ref().cloned().unwrap_or_default().into_iter().collect();
    let new_kws: HashSet<String> = new.forbidden_keywords.as_ref().cloned().unwrap_or_default().into_iter().collect();

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
        println!("\n{}: {:?} -> {:?}", "Context Window".yellow(), old.context_window, new.context_window);
    }

    println!("\n{}", "--- End Diff ---".bold());
}

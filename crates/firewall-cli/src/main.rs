use clap::{Parser, Subcommand};
use firewall_core::{evaluate_raw, init, config::FirewallConfig};
use std::io::{self, BufRead};
use std::path::PathBuf;

mod diff;

#[derive(Parser)]
#[command(name = "firewall-cli")]
#[command(about = "Policy-Gate Management CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate prompts from stdin (line-by-line).
    Eval {
        /// Optional path to a specific firewall.toml.
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Compare two firewall configuration files.
    Diff {
        /// Base configuration file.
        path_a: PathBuf,
        /// New configuration file to compare against.
        path_b: PathBuf,
    },
    /// Validate a firewall configuration file.
    Validate {
        /// Path to the configuration file.
        path: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Eval { config: _ } => {
            // For now, eval still uses standard init() which loads firewall.toml.
            init().expect("firewall init failed");

            let stdin = io::stdin();
            for (i, line) in stdin.lock().lines().enumerate() {
                let prompt = match line {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("read error: {}", e);
                        continue;
                    }
                };
                if prompt.trim().is_empty() {
                    continue;
                }
                let verdict = evaluate_raw(prompt.clone(), i as u64);
                let label = if verdict.is_pass() { "PASS" } else { "BLOCK" };
                println!("{}\t{:?}\t{}", label, verdict.kind, prompt);
            }
        }
        Commands::Diff { path_a, path_b } => {
            let cfg_a = FirewallConfig::load_from_path(&path_a).expect("Failed to load config A");
            let cfg_b = FirewallConfig::load_from_path(&path_b).expect("Failed to load config B");
            diff::display_diff(&cfg_a, &cfg_b);
        }
        Commands::Validate { path } => {
            match FirewallConfig::load_from_path(&path) {
                Ok(cfg) => {
                    if let Err(errors) = cfg.validate() {
                        eprintln!("Validation failed for {}:", path.display());
                        for err in errors {
                            eprintln!("  - {}", err);
                        }
                        std::process::exit(1);
                    } else {
                        println!("Configuration {} is VALID.", path.display());
                    }
                }
                Err(e) => {
                    eprintln!("Failed to load {}: {}", path.display(), e);
                    std::process::exit(1);
                }
            }
        }
    }
}

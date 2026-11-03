use tracing_subscriber::EnvFilter;

use sni_spoof_rs::{run_proxy_until_signal, scan};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    match raw_args.first().map(|s| s.as_str()) {
        Some("scan") => scan::run(&raw_args[1..]),
        Some("-h") | Some("--help") => print_top_level_help(),
        _ => {
            let config_path = raw_args
                .into_iter()
                .next()
                .unwrap_or_else(|| "config.json".into());
            if let Err(e) = run_proxy_until_signal(&config_path) {
                tracing::error!("{}", e);
                tracing::error!("{}", sni_spoof_rs::platform_privilege_hint());
                std::process::exit(1);
            }
        }
    }
}

fn print_top_level_help() {
    eprintln!("sni-spoof-rs -- DPI bypass via fake TLS ClientHello injection");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  sni-spoof-rs [CONFIG]        run as proxy (default: config.json)");
    eprintln!("  sni-spoof-rs scan [OPTS]     probe SNIs for fake_sni candidates");
    eprintln!();
    eprintln!("Run 'sni-spoof-rs scan --help' for scan options.");
}

use clap::Parser;
use colored::*;

mod cli;
mod crawler;
mod fuzzer;
mod http;
mod payloads;
mod reporter;
mod scanner;
mod waf;

use cli::Args;
use scanner::Scanner;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if !args.no_banner {
        print_banner();
        eprintln!(
            "{}\n",
            "WARNING: Only use against systems you own or have explicit written authorization to test."
                .yellow()
                .bold()
        );
    }

    let scanner = Scanner::new(args).await?;
    scanner.run().await?;

    Ok(())
}

fn print_banner() {
    println!(
        "{}",
        r"
 __  _____ ___                  _    
 \ \/ / __/ __| ___ __ _ _ _ __| |_  
  >  <\__ \__ \/ -_) _` | '_/ _| ' \ 
 /_/\_\___/___/\___\__,_|_| \__|_||_|
"
        .cyan()
        .bold()
    );
    println!(
        "  {} - Advanced XSS Detection tool",
        format!("XSSearch {}", env!("CARGO_PKG_VERSION")).cyan()
    );
    println!(
        "  {}",
        "(c) affolter engineering 2024-2026".dimmed()
    );
    println!();
}

use anyhow::Result;
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Info => write!(f, "Info"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub url: String,
    pub param: String,
    pub payload: String,
    pub method: String,
    pub context: String,
    pub severity: Severity,
    pub description: String,
}

pub struct Reporter<'a> {
    findings: &'a [Finding],
    verbose: bool,
}

impl<'a> Reporter<'a> {
    pub fn new(findings: &'a [Finding], verbose: bool) -> Self {
        Self { findings, verbose }
    }

    pub fn print_summary(&self) {
        let high = self.findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();
        let medium = self.findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count();
        let info = self.findings.iter().filter(|f| matches!(f.severity, Severity::Info)).count();

        println!("\n{}", "─".repeat(60).dimmed());
        println!("{}", "[Summary]".cyan().bold());

        if self.findings.is_empty() {
            println!("  No vulnerabilities found.");
            return;
        }

        if high > 0 {
            println!("  {} High severity findings", high.to_string().red().bold());
        }
        if medium > 0 {
            println!("  {} Medium severity findings", medium.to_string().yellow());
        }
        if info > 0 {
            println!("  {} Info findings (DOM sinks/no confirmed source)", info.to_string().dimmed());
        }

        println!("\n{}", "[Findings]".cyan().bold());
        for (i, f) in self.findings.iter().enumerate() {
            let sev = match f.severity {
                Severity::High => f.severity.to_string().red().bold().to_string(),
                Severity::Medium => f.severity.to_string().yellow().to_string(),
                _ => f.severity.to_string().dimmed().to_string(),
            };
            println!(
                "  {:>2}. [{}] {} | param={} | method={}",
                i + 1,
                sev,
                f.url,
                f.param.yellow(),
                f.method
            );
            if self.verbose {
                println!("       payload: {}", f.payload.cyan());
                println!("       context: {} | {}", f.context, f.description);
            }
        }
    }

    pub fn write_json(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self.findings)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

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
            Severity::High   => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low    => write!(f, "Low"),
            Severity::Info   => write!(f, "Info"),
        }
    }
}

impl Severity {
    fn emoji(&self) -> &'static str {
        match self {
            Severity::High   => "🔴",
            Severity::Medium => "🟠",
            Severity::Low    => "🟡",
            Severity::Info   => "🔵",
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
        let high   = self.count(|f| matches!(f.severity, Severity::High));
        let medium = self.count(|f| matches!(f.severity, Severity::Medium));
        let info   = self.count(|f| matches!(f.severity, Severity::Info));

        println!("\n{}", "─".repeat(60).dimmed());
        println!("{}", "[Summary]".cyan().bold());

        if self.findings.is_empty() {
            println!("  No vulnerabilities found.");
            return;
        }

        if high   > 0 { println!("  {} High severity findings",   high.to_string().red().bold()); }
        if medium > 0 { println!("  {} Medium severity findings", medium.to_string().yellow()); }
        if info   > 0 { println!("  {} Info findings (DOM sinks/no confirmed source)", info.to_string().dimmed()); }

        println!("\n{}", "[Findings]".cyan().bold());
        for (i, f) in self.findings.iter().enumerate() {
            let sev = match f.severity {
                Severity::High   => f.severity.to_string().red().bold().to_string(),
                Severity::Medium => f.severity.to_string().yellow().to_string(),
                _                => f.severity.to_string().dimmed().to_string(),
            };
            println!(
                "  {:>2}. [{}] {} | param={} | method={}",
                i + 1, sev, f.url, f.param.yellow(), f.method
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

    pub fn write_markdown(&self, path: &str) -> Result<()> {
        let md = self.render_markdown();
        std::fs::write(path, md)?;
        Ok(())
    }

    fn render_markdown(&self) -> String {
        let mut out = String::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Header
        out.push_str("# XSSearch — Scan Report\n\n");
        out.push_str(&format!("**Generated:** {}\n\n", format_unix(now)));

        // Summary table
        let high   = self.count(|f| matches!(f.severity, Severity::High));
        let medium = self.count(|f| matches!(f.severity, Severity::Medium));
        let low    = self.count(|f| matches!(f.severity, Severity::Low));
        let info   = self.count(|f| matches!(f.severity, Severity::Info));

        out.push_str("## Summary\n\n");
        out.push_str("| Severity | Count |\n");
        out.push_str("| --- | --- |\n");
        out.push_str(&format!("| {} High | {} |\n",   Severity::High.emoji(),   high));
        out.push_str(&format!("| {} Medium | {} |\n", Severity::Medium.emoji(), medium));
        out.push_str(&format!("| {} Low | {} |\n",    Severity::Low.emoji(),    low));
        out.push_str(&format!("| {} Info | {} |\n",   Severity::Info.emoji(),   info));
        out.push_str(&format!("| **Total** | **{}** |\n\n", self.findings.len()));

        if self.findings.is_empty() {
            out.push_str("No vulnerabilities found.\n");
            return out;
        }

        // Per-finding sections
        out.push_str("## Findings\n\n");
        for (i, f) in self.findings.iter().enumerate() {
            out.push_str(&format!(
                "### {}. {} [{}] `{}`\n\n",
                i + 1,
                f.severity.emoji(),
                f.severity,
                f.param,
            ));

            out.push_str("| Field | Value |\n");
            out.push_str("| --- | --- |\n");
            out.push_str(&format!("| **URL** | `{}` |\n",         md_escape(&f.url)));
            out.push_str(&format!("| **Parameter** | `{}` |\n",   md_escape(&f.param)));
            out.push_str(&format!("| **Method** | `{}` |\n",      f.method));
            out.push_str(&format!("| **Severity** | {} {} |\n",   f.severity.emoji(), f.severity));
            out.push_str(&format!("| **Context** | `{}` |\n",     md_escape(&f.context)));
            out.push_str(&format!("| **Description** | {} |\n",   md_escape(&f.description)));
            out.push('\n');

            out.push_str("**Payload**\n\n");
            out.push_str("```html\n");
            out.push_str(&f.payload);
            out.push_str("\n```\n\n");

            out.push_str("---\n\n");
        }

        // Quick-reference table
        out.push_str("## All Findings (Quick Reference)\n\n");
        out.push_str("| # | Severity | Method | Parameter | URL |\n");
        out.push_str("| --- | --- | --- | --- | --- |\n");
        for (i, f) in self.findings.iter().enumerate() {
            out.push_str(&format!(
                "| {} | {} {} | `{}` | `{}` | `{}` |\n",
                i + 1,
                f.severity.emoji(),
                f.severity,
                f.method,
                md_escape(&f.param),
                md_escape(&f.url),
            ));
        }
        out.push('\n');

        out
    }

    fn count(&self, pred: impl Fn(&Finding) -> bool) -> usize {
        self.findings.iter().filter(|f| pred(f)).count()
    }
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('`', "\\`")
}

fn format_unix(secs: u64) -> String {
    // RFC 3339-like without pulling in chrono: YYYY-MM-DD HH:MM:SS UTC
    let s = secs;
    let (mut y, mut mo, mut d, mut h, mut mi, mut sec) = (1970u64, 1u64, 1u64, 0u64, 0u64, 0u64);
    sec = s % 60; let s = s / 60;
    mi  = s % 60; let s = s / 60;
    h   = s % 24; let mut days = s / 24;
    // rough Gregorian calculation
    y = 1970 + days / 365;
    days %= 365;
    let months = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for (idx, &mlen) in months.iter().enumerate() {
        if days < mlen { mo = idx as u64 + 1; d = days + 1; break; }
        days -= mlen;
    }
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, mo, d, h, mi, sec)
}

/// Static DOM XSS analysis  - identifies dangerous source/sink patterns in JS/HTML.

use crate::reporter::{Finding, Severity};
use regex::Regex;

#[derive(Debug)]
struct Sink {
    pattern: &'static str,
    description: &'static str,
    severity: Severity,
}

const SINKS: &[Sink] = &[
    Sink { pattern: r"\.createContextualFragment\s*\(", description: "createContextualFragment()", severity: Severity::High },
    Sink { pattern: r"\.href\s*=", description: ".href assignment", severity: Severity::Medium },
    Sink { pattern: r"\.src\s*=", description: ".src assignment", severity: Severity::Medium },
    Sink { pattern: r"document\.write\s*\(", description: "document.write()", severity: Severity::High },
    Sink { pattern: r"document\.writeln\s*\(", description: "document.writeln()", severity: Severity::High },
    Sink { pattern: r"eval\s*\(", description: "eval()", severity: Severity::High },
    Sink { pattern: r"innerHTML\s*=", description: "innerHTML assignment", severity: Severity::High },
    Sink { pattern: r"insertAdjacentHTML\s*\(", description: "insertAdjacentHTML()", severity: Severity::High },
    Sink { pattern: r"location\.assign\s*\(", description: "location.assign()", severity: Severity::High },
    Sink { pattern: r"location\.href\s*=", description: "location.href assignment", severity: Severity::High },
    Sink { pattern: r"location\.replace\s*\(", description: "location.replace()", severity: Severity::High },
    Sink { pattern: r"outerHTML\s*=", description: "outerHTML assignment", severity: Severity::High },
    Sink { pattern: r#"\$\s*\(\s*["'][^"']*["']\s*\)\.html\s*\("#, description: "jQuery .html()", severity: Severity::High },
    Sink { pattern: r#"setInterval\s*\(\s*["']"#, description: "setInterval with string", severity: Severity::High },
    Sink { pattern: r#"setTimeout\s*\(\s*["']"#, description: "setTimeout with string", severity: Severity::High },
];

const SOURCES: &[&str] = &[
    r"document\.cookie",
    r"document\.referrer",
    r"localStorage\.",
    r"location\.hash",
    r"location\.href",
    r"location\.search",
    r"sessionStorage\.",
    r"URLSearchParams",
    r"window\.name",
];

pub fn analyze(html: &str, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let source_present = SOURCES.iter().any(|src| {
        Regex::new(src).map_or(false, |re| re.is_match(html))
    });

    for sink in SINKS {
        if let Ok(re) = Regex::new(sink.pattern) {
            if re.is_match(html) {
                let severity = if source_present {
                    sink.severity.clone()
                } else {
                    Severity::Info
                };

                findings.push(Finding {
                    url: url.to_string(),
                    param: "dom".into(),
                    payload: sink.pattern.to_string(),
                    method: "STATIC".into(),
                    context: "dom-sink".into(),
                    severity,
                    description: format!(
                        "DOM sink: {} {}",
                        sink.description,
                        if source_present { "(user-controlled source found nearby)" } else { "" }
                    ),
                });
            }
        }
    }

    findings
}

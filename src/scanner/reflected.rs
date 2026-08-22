use crate::{
    http::HttpClient,
    payloads::html_payloads,
    reporter::{Finding, Severity},
};
use anyhow::Result;
use colored::*;
use std::collections::HashMap;

const INJECTABLE_HEADERS: &[&str] = &[
    "Referer",
    "User-Agent",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "X-Custom-IP-Authorization",
    "X-Original-URL",
    "Client-IP",
    "True-Client-IP",
    "Forwarded",
];

pub async fn test_headers(
    client: &HttpClient,
    url: &str,
    _verbose: bool,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let payloads = html_payloads();

    for header in INJECTABLE_HEADERS {
        for payload in payloads.iter().take(5) {
            let mut extra: HashMap<String, String> = HashMap::new();
            extra.insert(header.to_string(), payload.raw.clone());

            let resp = match client.request(reqwest::Method::GET, url, None, Some(&extra)).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if resp.body.contains(&payload.raw) {
                let finding = Finding {
                    url: url.to_string(),
                    param: header.to_string(),
                    payload: payload.raw.clone(),
                    method: "GET".into(),
                    context: "header".into(),
                    severity: Severity::High,
                    description: format!("Reflected XSS via {} header", header),
                };
                println!(
                    "    {} XSS in header '{}' | {}",
                    "[Vuln]".red().bold(),
                    header.yellow(),
                    payload.raw.cyan()
                );
                findings.push(finding);
                break; // one per header
            }
        }
    }

    Ok(findings)
}

pub async fn test_cookies(
    client: &HttpClient,
    url: &str,
    cookie_str: &str,
    _verbose: bool,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let payloads = html_payloads();

    // Parse cookie names from the provided cookie string
    let cookie_names: Vec<&str> = cookie_str
        .split(';')
        .filter_map(|p| p.trim().split_once('=').map(|(k, _)| k.trim()))
        .collect();

    for name in &cookie_names {
        for payload in payloads.iter().take(5) {
            // Build modified cookie string with payload in this cookie
            let injected_cookie = cookie_str
                .split(';')
                .map(|part| {
                    let part = part.trim();
                    if let Some((k, _)) = part.split_once('=') {
                        if k.trim() == *name {
                            return format!("{}={}", k.trim(), payload.raw);
                        }
                    }
                    part.to_string()
                })
                .collect::<Vec<_>>()
                .join("; ");

            let mut extra: HashMap<String, String> = HashMap::new();
            extra.insert("Cookie".to_string(), injected_cookie);

            let resp = match client.request(reqwest::Method::GET, url, None, Some(&extra)).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if resp.body.contains(&payload.raw) {
                let finding = Finding {
                    url: url.to_string(),
                    param: format!("cookie:{}", name),
                    payload: payload.raw.clone(),
                    method: "GET".into(),
                    context: "cookie".into(),
                    severity: Severity::High,
                    description: format!("Reflected XSS via cookie '{}'", name),
                };
                println!(
                    "    {} XSS in cookie '{}' | {}",
                    "[Vuln]".red().bold(),
                    name.yellow(),
                    payload.raw.cyan()
                );
                findings.push(finding);
                break;
            }
        }
    }

    Ok(findings)
}

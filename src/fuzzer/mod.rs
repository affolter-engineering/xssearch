#![allow(dead_code)]

use crate::{
    crawler::DiscoveredTarget,
    http::HttpClient,
    payloads::Payload,
    reporter::Finding,
};
use anyhow::Result;
use colored::*;

pub struct Fuzzer {
    client: HttpClient,
    verbose: bool,
}

impl Fuzzer {
    pub fn new(client: HttpClient, verbose: bool) -> Self {
        Self { client, verbose }
    }

    /// Fuzz all parameters of a target with a given payload set.
    pub async fn fuzz_target(
        &self,
        target: &DiscoveredTarget,
        payloads: &[Payload],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for param in &target.params {
            for payload in payloads {
                let result = self.test_payload(target, param, &payload.raw).await;
                match result {
                    Ok(Some(finding)) => {
                        println!(
                            "  {} {} in '{}' | {}",
                            "[FUZZ]".red().bold(),
                            "HIT".red().bold(),
                            param.yellow(),
                            payload.raw.cyan()
                        );
                        findings.push(finding);
                        break; // one hit per param
                    }
                    Err(e) if self.verbose => {
                        eprintln!("  [ERR] fuzz: {}", e);
                    }
                    _ => {}
                }
            }
        }

        Ok(findings)
    }

    async fn test_payload(
        &self,
        target: &DiscoveredTarget,
        param: &str,
        payload: &str,
    ) -> Result<Option<Finding>> {
        let (body, resp_url) = if target.method == "POST" {
            let data = target
                .post_data
                .as_deref()
                .map(|d| crate::http::inject_data(d, param, payload))
                .unwrap_or_default();
            let r = self.client.post(&target.url, &data).await?;
            (r.body, r.url)
        } else {
            let url = crate::http::inject_param_url(&target.url, param, payload)?;
            let r = self.client.get(&url).await?;
            (r.body, r.url)
        };

        if body.contains(payload) || body.to_ascii_lowercase().contains("alert(") {
            Ok(Some(Finding {
                url: resp_url,
                param: param.to_string(),
                payload: payload.to_string(),
                method: target.method.clone(),
                context: "fuzz".into(),
                severity: crate::reporter::Severity::High,
                description: "Payload reflected in response".into(),
            }))
        } else {
            Ok(None)
        }
    }
}

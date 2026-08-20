pub mod reflected;
pub mod dom;
pub mod blind;

use crate::{
    cli::Args,
    crawler::{Crawler, DiscoveredTarget},
    http::{parse_post_params, parse_query_params, HttpClient},
    payloads::{encoding::apply_encodings, get_payloads_for_set},
    reporter::{Finding, Reporter, Severity},
    waf::{print_waf_result, WafDetector, WafKind},
};
use anyhow::Result;
use colored::*;

pub struct Scanner {
    args: Args,
    client: HttpClient,
}

impl Scanner {
    pub async fn new(args: Args) -> Result<Self> {
        let client = HttpClient::new(
            &args.user_agent,
            args.cookie.as_deref(),
            args.proxy.as_deref(),
            args.timeout,
            args.follow_redirects,
            &args.headers,
            args.delay,
        )?;
        Ok(Self { args, client })
    }

    pub async fn run(&self) -> Result<()> {
        let mut findings: Vec<Finding> = Vec::new();

        // Collect URLs to scan
        let urls = self.collect_urls()?;

        for raw_url in &urls {
            println!("\n{} {}", "[Target]".cyan().bold(), raw_url);

            // WAF detection
            let mut waf = WafKind::None;
            if self.args.waf_detect || self.args.waf_bypass {
                waf = WafDetector::detect(&self.client, raw_url).await?;
                print_waf_result(&waf);
            }

            // DOM analysis
            if self.args.dom {
                let resp = self.client.get(raw_url).await?;
                let dom_findings = dom::analyze(&resp.body, raw_url);
                if !dom_findings.is_empty() {
                    println!("  {} Found {} DOM sink(s)", "[DOM]".yellow(), dom_findings.len());
                    findings.extend(dom_findings);
                }
            }

            // Crawl or use direct URL
            let targets = self.build_targets(raw_url).await?;

            if targets.is_empty() && !self.args.dom {
                println!("  {} No injectable parameters found", "[Skip]".dimmed());
                continue;
            }

            for target in targets {
                let target_findings = self
                    .scan_target(&target, &waf)
                    .await?;
                findings.extend(target_findings);
            }
        }

        // Report
        let reporter = Reporter::new(&findings, self.args.verbose);
        reporter.print_summary();

        if let Some(out) = &self.args.output {
            reporter.write_json(out)?;
            println!("\n{} Results written to {}", "[Output]".green(), out);
        }

        Ok(())
    }

    fn collect_urls(&self) -> Result<Vec<String>> {
        let mut urls = Vec::new();

        if let Some(u) = &self.args.url {
            urls.push(u.clone());
        }

        if let Some(file) = &self.args.urls_file {
            let content = std::fs::read_to_string(file)?;
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    urls.push(line.to_string());
                }
            }
        }

        Ok(urls)
    }

    async fn build_targets(&self, url: &str) -> Result<Vec<DiscoveredTarget>> {
        let mut targets = Vec::new();

        if self.args.crawl {
            println!("  {} Crawling (depth={}) ...", "[Crawl]".cyan(), self.args.crawl_depth);
            let mut crawler = Crawler::new(self.client.clone(), url, self.args.crawl_depth);
            let crawled = crawler.crawl().await?;
            println!("  {} {} target(s) discovered", "[Crawl]".cyan(), crawled.len());
            targets.extend(crawled);
        }

        // Direct URL parameters
        let url_params = if url.contains("FUZZ") {
            vec!["FUZZ".to_string()]
        } else {
            parse_query_params(url)
        };

        if !url_params.is_empty() {
            let clean_url = url.replace("FUZZ", "xssearch");
            targets.push(DiscoveredTarget {
                url: if url.contains("FUZZ") { clean_url } else { url.to_string() },
                method: "GET".into(),
                params: url_params,
                post_data: None,
            });
        }

        // POST data
        if let Some(data) = &self.args.data {
            let params = if data.contains("FUZZ") {
                vec!["FUZZ".to_string()]
            } else {
                parse_post_params(data)
            };
            if !params.is_empty() {
                targets.push(DiscoveredTarget {
                    url: url.to_string(),
                    method: "POST".into(),
                    params,
                    post_data: Some(data.clone()),
                });
            }
        }

        // Deduplicate by (base path, sorted param names)  - prevents crawled + direct URL double-scan
        let mut seen_keys = std::collections::HashSet::new();
        targets.retain(|t| {
            let base = url::Url::parse(&t.url)
                .map(|u| u.path().to_string())
                .unwrap_or(t.url.clone());
            let mut p = t.params.clone();
            p.sort();
            let key = format!("{}|{}", base, p.join(","));
            seen_keys.insert(key)
        });

        Ok(targets)
    }

    async fn scan_target(&self, target: &DiscoveredTarget, waf: &WafKind) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for param in &target.params {
            println!(
                "  {} {} {} [{}]",
                "[Param]".blue(),
                target.method,
                param,
                target.url
            );

            // Reflection probe
            let probe = format!("xss{}probe", rand_hex(4));
            let (probe_body, _probe_url) = self
                .send_probe(target, param, &probe)
                .await?;

            if !probe_body.contains(&probe) {
                if self.args.verbose {
                    println!("    {} not reflected", "[Probe]".dimmed());
                }
                if !self.args.fuzz {
                    continue;
                }
            }

            // Determine reflection context
            let ctx = if probe_body.contains(&probe) {
                let c = crate::payloads::generator::detect_context(&probe_body, &probe);
                if self.args.verbose {
                    println!("    {} context: {:?}", "[CTX]".dimmed(), c);
                }
                c
            } else {
                crate::payloads::generator::ReflectionContext::None
            };

            // Build payload list
            let mut payloads = if self.args.fuzz {
                get_payloads_for_set(&self.args.payload_set)
            } else {
                crate::payloads::generator::payloads_for_context(&ctx)
            };

            // Load custom payloads
            if let Some(pf) = &self.args.payloads_file {
                if let Ok(content) = std::fs::read_to_string(pf) {
                    for line in content.lines() {
                        let line = line.trim();
                        if !line.is_empty() {
                            payloads.push(crate::payloads::Payload {
                                raw: line.to_string(),
                                context: crate::payloads::PayloadContext::Html,
                                description: "custom",
                            });
                        }
                    }
                }
            }

            // Apply encodings
            let encodings: Vec<&str> = self
                .args
                .encode
                .as_deref()
                .map(|e| e.split(',').collect())
                .unwrap_or_default();

            // Test each payload
            'payload_loop: for payload in &payloads {
                let raw = payload.raw.clone();
                let raw = format!(
                    "{}{}{}",
                    self.args.prefix.as_deref().unwrap_or(""),
                    raw,
                    self.args.suffix.as_deref().unwrap_or("")
                );

                let mut candidates = vec![raw.clone()];

                // WAF bypass variants
                if self.args.waf_bypass && *waf != WafKind::None {
                    candidates.extend(crate::waf::WafDetector::bypass_payloads(waf, &raw));
                }

                // Encoding variants
                if !encodings.is_empty() {
                    let enc_variants = apply_encodings(&raw, &encodings);
                    candidates.extend(enc_variants);
                }

                for candidate in candidates {
                    let result = self
                        .send_payload(target, param, &candidate)
                        .await;

                    match result {
                        Ok((body, resp_url)) => {
                            if self.check_reflected(&body, &candidate) {
                                let finding = Finding {
                                    url: resp_url,
                                    param: param.clone(),
                                    payload: candidate.clone(),
                                    method: target.method.clone(),
                                    context: format!("{:?}", payload.context),
                                    severity: Severity::High,
                                    description: payload.description.to_string(),
                                };
                                println!(
                                    "    {} {} in '{}' | {}",
                                    "[Vuln]".red().bold(),
                                    "XSS".red().bold(),
                                    param.yellow(),
                                    candidate.cyan()
                                );
                                findings.push(finding);
                                break 'payload_loop; // one confirmed vuln per param is enough
                            }
                        }
                        Err(e) => {
                            if self.args.verbose {
                                eprintln!("    [Error] {}", e);
                            }
                        }
                    }
                }
            }

            // Blind XSS
            if let Some(ref callback) = self.args.blind {
                blind::inject(&self.client, target, param, callback, self.args.verbose).await?;
            }
        }

        // Header injection - once per target URL, not once per param
        if self.args.headers_inject {
            if self.args.verbose {
                println!("  {} Testing injectable headers ...", "[HDR]".blue());
            }
            let h_findings = reflected::test_headers(&self.client, &target.url, self.args.verbose).await?;
            findings.extend(h_findings);
        }

        // Cookie injection - once per target URL
        if self.args.cookie_inject {
            if let Some(ref cookie) = self.args.cookie {
                let c_findings = reflected::test_cookies(&self.client, &target.url, cookie, self.args.verbose).await?;
                findings.extend(c_findings);
            }
        }

        Ok(findings)
    }

    async fn send_probe(
        &self,
        target: &DiscoveredTarget,
        param: &str,
        probe: &str,
    ) -> Result<(String, String)> {
        self.send_payload(target, param, probe).await
    }

    async fn send_payload(
        &self,
        target: &DiscoveredTarget,
        param: &str,
        payload: &str,
    ) -> Result<(String, String)> {
        let real_payload = if param == "FUZZ" {
            target.url.replace("FUZZ", payload)
        } else {
            payload.to_string()
        };

        if target.method == "POST" {
            let data = target
                .post_data
                .as_deref()
                .map(|d| {
                    if param == "FUZZ" {
                        d.replace("FUZZ", &real_payload)
                    } else {
                        crate::http::inject_data(d, param, &real_payload)
                    }
                })
                .unwrap_or_default();

            let resp = self.client.post(&target.url, &data).await?;
            Ok((resp.body, resp.url))
        } else {
            let url = if param == "FUZZ" {
                target.url.replace("FUZZ", &real_payload)
            } else {
                crate::http::inject_param_url(&target.url, param, &real_payload)?
            };
            let resp = self.client.get(&url).await?;
            Ok((resp.body, resp.url))
        }
    }

    fn check_reflected(&self, body: &str, payload: &str) -> bool {
        // Check if the payload (or key parts) appear in the response unencoded
        let significant = extract_significant(payload);
        significant.iter().any(|s| body.contains(s.as_str()))
    }
}

fn extract_significant(payload: &str) -> Vec<String> {
    // Pull out distinctive substrings that indicate the payload executed/reflected
    let markers = ["alert(", "alert`", "prompt(", "confirm(", "onerror=", "onload=",
                    "onmouseover=", "onfocus=", "<script", "javascript:", "svg/onload",
                    "eval(", "document.cookie", "document.write"];
    let mut result = vec![payload.to_string()];
    for m in &markers {
        if payload.to_ascii_lowercase().contains(&m.to_ascii_lowercase()) {
            result.push(m.to_string());
        }
    }
    result
}

fn rand_hex(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..len).map(|_| format!("{:x}", rng.gen::<u8>() & 0xf)).collect()
}

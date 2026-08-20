use crate::http::HttpClient;
use anyhow::Result;
use scraper::{Html, Selector};
use std::collections::{HashSet, VecDeque};
use url::Url;

#[derive(Debug, Clone)]
pub struct DiscoveredTarget {
    pub url: String,
    pub method: String,
    pub params: Vec<String>,
    pub post_data: Option<String>,
}

pub struct Crawler {
    client: HttpClient,
    base_url: String,
    max_depth: usize,
    visited: HashSet<String>,
}

impl Crawler {
    pub fn new(client: HttpClient, base_url: &str, max_depth: usize) -> Self {
        Self {
            client,
            base_url: base_url.to_string(),
            max_depth,
            visited: HashSet::new(),
        }
    }

    pub async fn crawl(&mut self) -> Result<Vec<DiscoveredTarget>> {
        let mut targets = Vec::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        queue.push_back((self.base_url.clone(), 0));

        let base_host = Url::parse(&self.base_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_default();

        while let Some((url, depth)) = queue.pop_front() {
            if depth > self.max_depth || self.visited.contains(&url) {
                continue;
            }
            self.visited.insert(url.clone());

            let resp = match self.client.get(&url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let discovered = extract_targets(&url, &resp.body);

            for target in discovered {
                // Stay in scope  - same host
                if let Ok(parsed) = Url::parse(&target.url) {
                    if parsed.host_str().unwrap_or("") != base_host {
                        continue;
                    }
                }

                if !self.visited.contains(&target.url) && depth + 1 <= self.max_depth {
                    queue.push_back((target.url.clone(), depth + 1));
                }

                if !target.params.is_empty() || target.post_data.is_some() {
                    targets.push(target);
                }
            }
        }

        // Deduplicate targets by url+params key
        let mut seen = HashSet::new();
        targets.retain(|t| {
            let key = format!("{}|{}", t.url, t.params.join(","));
            seen.insert(key)
        });

        Ok(targets)
    }
}

fn extract_targets(base_url: &str, html: &str) -> Vec<DiscoveredTarget> {
    let document = Html::parse_document(html);
    let mut targets = Vec::new();

    // <a href="..."> links with query params
    if let Ok(sel) = Selector::parse("a[href]") {
        for el in document.select(&sel) {
            if let Some(href) = el.value().attr("href") {
                let resolved = resolve_url(base_url, href);
                if let Some(url) = resolved {
                    let params = crate::http::parse_query_params(&url);
                    if !params.is_empty() {
                        targets.push(DiscoveredTarget {
                            url,
                            method: "GET".into(),
                            params,
                            post_data: None,
                        });
                    } else {
                        // Link without params  - still worth crawling
                        targets.push(DiscoveredTarget {
                            url,
                            method: "GET".into(),
                            params: vec![],
                            post_data: None,
                        });
                    }
                }
            }
        }
    }

    // <form> elements
    if let Ok(sel) = Selector::parse("form") {
        for form in document.select(&sel) {
            let action = form.value().attr("action").unwrap_or(base_url);
            let method = form.value().attr("method").unwrap_or("GET").to_uppercase();
            let resolved_action = resolve_url(base_url, action).unwrap_or(base_url.to_string());

            let mut fields: Vec<(String, String)> = Vec::new();
            if let Ok(input_sel) = Selector::parse("input, select, textarea") {
                for input in form.select(&input_sel) {
                    let name = input.value().attr("name").unwrap_or("").to_string();
                    let value = input.value().attr("value").unwrap_or("").to_string();
                    if !name.is_empty() {
                        fields.push((name, value));
                    }
                }
            }

            let params: Vec<String> = fields.iter().map(|(n, _)| n.clone()).collect();
            let post_data = if method == "POST" {
                Some(
                    fields
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<_>>()
                        .join("&"),
                )
            } else {
                None
            };

            let url = if method == "GET" && !fields.is_empty() {
                let query: String = fields
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("&");
                format!("{}?{}", resolved_action.trim_end_matches('?'), query)
            } else {
                resolved_action
            };

            if !params.is_empty() {
                targets.push(DiscoveredTarget {
                    url,
                    method,
                    params,
                    post_data,
                });
            }
        }
    }

    targets
}

fn resolve_url(base: &str, href: &str) -> Option<String> {
    if href.starts_with("javascript:") || href.starts_with("mailto:") || href.starts_with('#') {
        return None;
    }
    let base_url = Url::parse(base).ok()?;
    base_url.join(href).ok().map(|u| u.to_string())
}

use anyhow::{Context, Result};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, COOKIE, USER_AGENT},
    Client, Method, Response,
};
use std::{collections::HashMap, str::FromStr, time::Duration};
use url::Url;

#[derive(Clone, Debug)]
pub struct HttpClient {
    client: Client,
    pub base_headers: HeaderMap,
    pub delay_ms: u64,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub url: String,
}

impl HttpClient {
    pub fn new(
        user_agent: &str,
        cookie: Option<&str>,
        proxy: Option<&str>,
        timeout_secs: u64,
        follow_redirects: bool,
        extra_headers: &[String],
        delay_ms: u64,
    ) -> Result<Self> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(true)
            .connection_verbose(false);

        if !follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }

        if let Some(proxy_url) = proxy {
            let proxy = reqwest::Proxy::all(proxy_url)?;
            builder = builder.proxy(proxy);
        }

        let client = builder.build()?;

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(user_agent)?);

        if let Some(c) = cookie {
            headers.insert(COOKIE, HeaderValue::from_str(c)?);
        }

        for h in extra_headers {
            if let Some((name, value)) = h.split_once(':') {
                let name = name.trim();
                let value = value.trim();
                if let (Ok(n), Ok(v)) = (HeaderName::from_str(name), HeaderValue::from_str(value)) {
                    headers.insert(n, v);
                }
            }
        }

        Ok(Self { client, base_headers: headers, delay_ms })
    }

    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        self.request(Method::GET, url, None, None).await
    }

    pub async fn post(&self, url: &str, body: &str) -> Result<HttpResponse> {
        self.request(Method::POST, url, Some(body), None).await
    }

    pub async fn request(
        &self,
        method: Method,
        url: &str,
        body: Option<&str>,
        extra_headers: Option<&HashMap<String, String>>,
    ) -> Result<HttpResponse> {
        if self.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        }

        let mut req = self.client.request(method, url).headers(self.base_headers.clone());

        if let Some(extra) = extra_headers {
            for (k, v) in extra {
                if let (Ok(name), Ok(val)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
                    req = req.header(name, val);
                }
            }
        }

        if let Some(b) = body {
            req = req.body(b.to_string()).header("Content-Type", "application/x-www-form-urlencoded");
        }

        let resp: Response = req.send().await.context("HTTP request failed")?;

        let status = resp.status().as_u16();
        let resp_url = resp.url().to_string();
        let mut headers = HashMap::new();
        for (k, v) in resp.headers() {
            headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
        }
        let body_text = resp.text().await.unwrap_or_default();

        Ok(HttpResponse { status, headers, body: body_text, url: resp_url })
    }
}

pub fn inject_param_url(url: &str, param: &str, payload: &str) -> Result<String> {
    let mut parsed = Url::parse(url)?;
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| {
            if k == param {
                (k.to_string(), payload.to_string())
            } else {
                (k.to_string(), v.to_string())
            }
        })
        .collect();

    parsed.query_pairs_mut().clear();
    for (k, v) in &pairs {
        parsed.query_pairs_mut().append_pair(k, v);
    }
    Ok(parsed.to_string())
}

pub fn inject_data(data: &str, param: &str, payload: &str) -> String {
    let pairs: Vec<&str> = data.split('&').collect();
    pairs
        .iter()
        .map(|p| {
            if let Some((k, _)) = p.split_once('=') {
                if k == param {
                    return format!("{}={}", k, url_encode_minimal(payload));
                }
            }
            p.to_string()
        })
        .collect::<Vec<_>>()
        .join("&")
}

pub fn url_encode_minimal(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            ' ' => out.push('+'),
            '&' | '=' | '+' | '%' | '#' => {
                out.push('%');
                out.push_str(&format!("{:02X}", c as u32));
            }
            _ => out.push(c),
        }
    }
    out
}

pub fn parse_query_params(url: &str) -> Vec<String> {
    Url::parse(url)
        .map(|u| u.query_pairs().map(|(k, _)| k.to_string()).collect())
        .unwrap_or_default()
}

pub fn parse_post_params(data: &str) -> Vec<String> {
    data.split('&')
        .filter_map(|p| p.split_once('=').map(|(k, _)| k.to_string()))
        .collect()
}

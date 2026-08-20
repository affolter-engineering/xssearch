use base64::{engine::general_purpose::STANDARD, Engine as _};

pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

pub fn double_url_encode(s: &str) -> String {
    url_encode(&url_encode(s))
}

pub fn html_encode(s: &str) -> String {
    s.chars()
        .map(|c| format!("&#{};", c as u32))
        .collect()
}

pub fn unicode_encode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c.is_ascii_whitespace() {
                c.to_string()
            } else {
                format!("\\u{:04X}", c as u32)
            }
        })
        .collect()
}

pub fn hex_encode_js(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("\\x{:02X}", c as u32)
            }
        })
        .collect()
}

pub fn base64_encode(s: &str) -> String {
    STANDARD.encode(s)
}

/// Wrap payload so it evaluates via eval(atob('...'))
pub fn base64_eval_wrap(s: &str) -> String {
    format!("eval(atob('{}'))", base64_encode(s))
}

pub fn apply_encodings(payload: &str, encodings: &[&str]) -> Vec<String> {
    let mut results = vec![payload.to_string()];
    for enc in encodings {
        let encoded = match *enc {
            "url" => url_encode(payload),
            "double" => double_url_encode(payload),
            "html" => html_encode(payload),
            "unicode" => unicode_encode(payload),
            "base64" => format!("<img src=x onerror={}>", base64_eval_wrap(payload)),
            _ => continue,
        };
        results.push(encoded);
    }
    results
}

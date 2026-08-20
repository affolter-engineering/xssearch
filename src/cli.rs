use clap::{Parser, ArgGroup};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "xssearch",
    version = env!("CARGO_PKG_VERSION"),
    about = "Advanced XSS detection tool",
    long_about = None,
    group(ArgGroup::new("target").required(true).args(["url", "urls_file"]))
)]
pub struct Args {
    // Target
    #[arg(short = 'u', long, help = "Target URL (use FUZZ to mark injection point)")]
    pub url: Option<String>,

    #[arg(short = 'f', long = "file", help = "File with list of URLs (one per line)")]
    pub urls_file: Option<String>,

    // Request options
    #[arg(short = 'd', long, help = "POST data (use FUZZ to mark injection point)")]
    pub data: Option<String>,

    #[arg(short = 'H', long = "header", help = "Extra header (repeatable: -H 'X-Foo: bar')", action = clap::ArgAction::Append)]
    pub headers: Vec<String>,

    #[arg(long, help = "Cookie string")]
    pub cookie: Option<String>,

    #[arg(long, help = "HTTP proxy (e.g. http://127.0.0.1:8080)")]
    pub proxy: Option<String>,

    #[arg(long, default_value = "10", help = "Request timeout in seconds")]
    pub timeout: u64,

    #[arg(long, default_value = "xssearch/1.0", help = "User-Agent string")]
    pub user_agent: String,

    #[arg(long, help = "Follow redirects")]
    pub follow_redirects: bool,

    #[arg(long, default_value = "2", help = "Concurrent requests")]
    pub threads: usize,

    #[arg(long, default_value = "0", help = "Delay between requests in ms")]
    pub delay: u64,

    // Scan modes
    #[arg(long, help = "Enable crawler to discover pages and parameters")]
    pub crawl: bool,

    #[arg(long, default_value = "3", help = "Crawl depth")]
    pub crawl_depth: usize,

    #[arg(long, help = "Test HTTP headers (Referer, User-Agent, X-Forwarded-For, etc.)")]
    pub headers_inject: bool,

    #[arg(long, help = "Test cookie values")]
    pub cookie_inject: bool,

    #[arg(long, help = "Blind XSS  - inject callback URL into all sinks")]
    pub blind: Option<String>,

    #[arg(long, help = "DOM XSS analysis (static source inspection)")]
    pub dom: bool,

    #[arg(long, help = "Fuzz mode  - try all payloads regardless of reflection analysis")]
    pub fuzz: bool,

    // Payload options
    #[arg(long, default_value = "all", help = "Payload set: all | html | js | attr | poly | dom")]
    pub payload_set: String,

    #[arg(long, help = "Custom payload file (one per line)")]
    pub payloads_file: Option<String>,

    #[arg(long, help = "Encode payloads: url | html | unicode | double | base64 (comma-separated)")]
    pub encode: Option<String>,

    #[arg(long, help = "Prepend string to every payload")]
    pub prefix: Option<String>,

    #[arg(long, help = "Append string to every payload")]
    pub suffix: Option<String>,

    // WAF options
    #[arg(long, help = "Detect WAF before scanning")]
    pub waf_detect: bool,

    #[arg(long, help = "Enable WAF bypass techniques")]
    pub waf_bypass: bool,

    // Output
    #[arg(short = 'o', long, help = "Output file (JSON)")]
    pub output: Option<String>,

    #[arg(short = 'v', long, help = "Verbose output")]
    pub verbose: bool,

    #[arg(long, help = "Suppress banner")]
    pub no_banner: bool,
}

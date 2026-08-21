# xssearch

Advanced XSS detection tool written in Rust, combining context-aware payload intelligence with the injection breadth.

This tool was inspired XSStrike and XSSER.

> **Warning**: Only use against systems you own or have explicit written authorization to test.

## Features

- **Context-aware scanning** - probes each parameter first, detects where the value reflects (HTML body, attribute, JavaScript, comment, `<title>`, `<textarea>`, etc.) and selects the most appropriate payloads for that context rather than blindly firing everything
- **100+ built-in payloads** - HTML tags, attribute breakouts, JS injection, polyglots, DOM sinks, WAF bypass variants
- **WAF detection & bypass** - fingerprints Cloudflare, ModSecurity, Sucuri, Imperva, Akamai, AWS WAF, F5 BIG-IP, Barracuda, Wordfence; applies per-WAF bypass transforms (case mutation, comment insertion, zero-width characters and encoding)
- **Crawler** - spiders links and forms to discover injectable parameters automatically
- **Header & cookie injection** - tests `Referer`, `User-Agent`, `X-Forwarded-For`, `X-Real-IP`, and other headers, plus cookie values
- **Blind XSS** - injects out-of-band callback payloads (compatible with Burp Collaborator, interactsh) into every sink for deferred execution scenarios (admin panels, log viewers and alike)
- **DOM XSS analysis** - static inspection of `innerHTML`, `eval`, `document.write`, `location.href`, jQuery `.html()`, and other dangerous sinks with source detection
- **Payload encoding** - URL, double-URL, HTML entity, Unicode and base64/eval encoding with composable flags
- **JSON output** - structured findings for integration with other tooling
- **Markdown report** - human-readable report with a severity summary table, per-finding detail sections, and a quick-reference table; ready to paste into a wiki or attach to a ticket
- **Pure Rust/rustls** - no OpenSSL dependency; single static-ish binary

## Installation

### From source (Nix)

```bash
git clone https://github.com/fabian-affolter/xssearch
cd xssearch
nix-shell --run "cargo build --release"
# binary: target/release/xssearch
```

Release build with LTO and stripped symbols:

```bash
nix-shell --argstr release true --run "$BUILD"
```

### From source (standard)

Requires Rust 1.75+.

```bash
cargo build --release
```

## Usage

```bash
xssearch [OPTIONS] <--url <URL> | --file <URLS_FILE>>
```

### Options

| Flag | Description |
| --- | --- |
| `-u, --url <URL>` | Target URL. Use `FUZZ` to mark a custom injection point |
| `-f, --file <FILE>` | File with one URL per line |
| `-d, --data <DATA>` | POST body. Use `FUZZ` to mark injection point |
| `-H, --header <H>` | Extra request header, repeatable |
| `--cookie <COOKIE>` | Cookie string |
| `--proxy <URL>` | HTTP/HTTPS proxy |
| `--timeout <N>` | Request timeout in seconds (default: 10) |
| `--user-agent <UA>` | Custom User-Agent |
| `--follow-redirects` | Follow HTTP redirects |
| `--threads <N>` | Concurrent requests (default: 2) |
| `--delay <MS>` | Delay between requests in milliseconds |
| `--crawl` | Spider the target for links and forms |
| `--crawl-depth <N>` | Crawl depth (default: 3) |
| `--headers-inject` | Test common HTTP headers as injection points |
| `--cookie-inject` | Test cookie values as injection points |
| `--blind <URL>` | Blind XSS callback URL |
| `--dom` | Static DOM XSS sink analysis |
| `--fuzz` | Fire all payloads regardless of reflection context |
| `--payload-set <SET>` | `all` \| `html` \| `js` \| `attr` \| `poly` \| `dom` (default: all) |
| `--payloads-file <FILE>` | Custom payload file, one per line |
| `--encode <LIST>` | Comma-separated encodings: `url,html,unicode,double,base64` |
| `--prefix <STR>` | Prepend string to every payload |
| `--suffix <STR>` | Append string to every payload |
| `--waf-detect` | Fingerprint WAF before scanning |
| `--waf-bypass` | Apply WAF bypass transforms to payloads |
| `--output-json <FILE>` | Write findings to JSON file |
| `--output-md <FILE>` | Write findings to Markdown file |
| `-v, --verbose` | Verbose output (show context, all probes) |

### Examples

#### Basic GET parameter scan

```bash
xssearch -u "https://example.com/search?q=test"
```

#### POST form

```bash
xssearch -u "https://example.com/login" -d "user=admin&pass=FUZZ"
```

#### Crawl from root, detect WAF, test headers

```bash
xssearch -u "https://example.com/" --crawl --waf-detect --headers-inject -v
```

#### WAF bypass with URL + HTML encoding

```bash
xssearch -u "https://example.com/?q=FUZZ" --waf-detect --waf-bypass --encode url,html
```

#### Blind XSS with interactsh callback

```bash
xssearch -u "https://example.com/contact" -d "msg=FUZZ" \
  --blind "https://abc123.oast.fun/xssearch"
```

#### DOM XSS static analysis only

```bash
xssearch -u "https://example.com/app" --dom --no-banner
```

#### Save results as JSON

```bash
xssearch -u "https://example.com/?q=test" --output-json results.json
```

#### Save results as Markdown

```bash
xssearch -u "https://example.com/?q=test" --output-md report.md
```

#### Save both formats at once

```bash
xssearch -f targets.txt --crawl --waf-detect --output-json results.json --output-md report.md
```

#### Proxy through Burp Suite

```bash
xssearch -u "https://example.com/?q=test" --proxy http://127.0.0.1:8080 -v
```

## Testing

### Local minimal target

The fastest way to verify the tool is to spin up an intentionally vulnerable Python server locally:

```bash
python3 - <<'EOF'
import http.server, urllib.parse

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query)
        val = q.get('q', [''])[0]
        body = f'<html><body><p>Search: {val}</p></body></html>'.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(body)

http.server.HTTPServer(('127.0.0.1', 9999), H).serve_forever()
EOF
```

Then scan it:

```bash
xssearch -u "http://127.0.0.1:9999/?q=test" -v
```

Expected output: `[VULN] XSS in 'q'` with an HTML-context payload.

### Local Docker targets

These images are purpose-built for security tool testing and contain no real user data.

#### DVWA (Damn Vulnerable Web Application)

```bash
docker run -d -p 8080:80 vulnerables/web-dvwa
# Set security level to Low in the UI first
xssearch -u "http://localhost:8080/vulnerabilities/xss_r/?name=test" \
  --cookie "PHPSESSID=<your-session>; security=low"
```

#### OWASP WebGoat

```bash
docker run -d -p 8081:8080 webgoat/goat-and-wolf
xssearch -u "http://localhost:8081/WebGoat/" --crawl --crawl-depth 2 -v
```

#### OWASP Juice Shop

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
xssearch -u "http://localhost:3000/" --crawl --dom -v
```

#### bWAPP

```bash
docker run -d -p 8082:80 raesene/bwapp
# Activate bWAPP at http://localhost:8082/install.php first
xssearch -u "http://localhost:8082/xss_get.php?firstname=test&lastname=test" \
  --cookie "PHPSESSID=<your-session>; security_level=0"
```

### Public intentionally vulnerable targets

These sites are provided specifically for security tool testing. No authentication or setup is needed.

| Target | URL | XSS entry points |
| --- | --- | --- |
| Acunetix test site | `http://testphp.vulnweb.com/` | `search.php?test=`, artist comments, search forms |
| IBM Altoro Mutual | `http://demo.testfire.net/` | search parameter, feedback form |
| HP WebInspect demo | `http://zero.webappsecurity.com/` | login form, search, account fields |
| Google Gruyere | `https://google-gruyere.appspot.com/` | snippets, profile fields (requires instance URL) |

#### Acunetix test site

Search parameter (reflected XSS):

```bash
xssearch -u "http://testphp.vulnweb.com/search.php?test=query" \
  --waf-detect -v
```

Full crawl with header injection:

```bash
xssearch -u "http://testphp.vulnweb.com/" \
  --crawl --crawl-depth 3 \
  --headers-inject \
  --dom \
  --output-json testphp-findings.json
```

#### IBM Altoro Mutual

Search form:

```bash
xssearch -u "http://demo.testfire.net/search.aspx?txtSearch=test" \
  --waf-detect --fuzz -v
```

#### HP WebInspect demo

Crawl from root:

```bash
xssearch -u "http://zero.webappsecurity.com/" \
  --crawl --crawl-depth 2 \
  --waf-detect \
  --output-json zero-findings.json
```

#### Google Gruyere

Start a personal instance first, then scan it:

```bash
# The instance URL is displayed after clicking "Start" on the Gruyere homepage
xssearch -u "https://google-gruyere.appspot.com/<instance-id>/feed.gtl" \
  --dom --crawl -v
```

Public targets can be intermittently slow or offline. Use `--timeout 30` if requests are timing out.

## Output

Terminal output uses color-coded labels:

| Label | Meaning |
| --- | --- |
| `[Target]` | URL being scanned |
| `[WAF]` | WAF detection result |
| `[Crawl]` | Crawler status |
| `[Param]` | Parameter under test |
| `[CTX]` | Detected reflection context |
| `[Vuln]` | Confirmed finding |
| `[DOM]` | DOM sink detected |
| `[Blind]` | Blind payload injected |

### JSON

One object per finding, written with `--output-json`:

```json
{
  "url": "https://example.com/search?q=%22+onmouseover%3Dalert%281%29+%22",
  "param": "q",
  "payload": "\" onmouseover=alert(1) \"",
  "method": "GET",
  "context": "Attribute",
  "severity": "High",
  "description": "attr breakout dquote onmouseover"
}
```

### Markdown

Written with `--output-md`, the report contains three sections:

**Summary table** — severity counts at a glance:

| Severity | Count |
| --- | --- |
| 🔴 High | 2 |
| 🟠 Medium | 0 |
| 🟡 Low | 0 |
| 🔵 Info | 0 |
| **Total** | **2** |

**Per-finding sections** — one heading per finding with a detail table and the payload in a fenced code block:

```markdown
### 1. 🔴 [High] `q`

| Field | Value |
| --- | --- |
| **URL** | `https://example.com/...` |
| **Parameter** | `q` |
| **Method** | `GET` |
| **Severity** | 🔴 High |
| **Context** | `Attribute` |
| **Description** | attr breakout dquote onmouseover |

**Payload**

​```html
" onmouseover=alert(1) "
​```
```

**Quick-reference table** — all findings in one flat table for easy scanning and copy-paste into tickets.

## Reflection contexts

| Context | Example | Payloads used |
| --- | --- | --- |
| `InsideHtmlTag` | `<p>PROBE</p>` | `<script>`, `<img onerror>`, `<svg onload>`,  ... |
| `InsideAttribute` | `value="PROBE"` | `" onmouseover=`, `"><script>`,  ... |
| `AttributeNoQuote` | `value=PROBE` | `onmouseover=`, space-terminated events |
| `InsideScript` | `var x = "PROBE"` | `';alert(1)//`, `"-alert(1)-"`,  ... |
| `InsideComment` | `<!-- PROBE -->` | `--><script>`,  ... |
| `InsideTitle` | `<title>PROBE</title>` | `</title><script>`,  ... |
| `InsideTextarea` | `<textarea>PROBE` | `</textarea><script>`,  ... |
| `InsideStyle` | `<style>PROBE` | `</style><script>`,  ... |

## Development

```bash
# Enter dev shell (provides gcc, rustc, cargo, cargo-watch)
nix-shell

# Auto-rebuild on changes
cargo watch -x 'build'

# Run tests
cargo test

# Lint
cargo clippy
```

## Legal

This tool is provided for authorized security testing, penetration testing engagements, CTF competitions and security research only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain explicit written permission before testing any system you do not own.

## License

MIT

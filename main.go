package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── ANSI Colors ───────────────────────────────────────────────────────────────
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[97m"
	orange  = "\033[38;5;208m"
	pink    = "\033[38;5;213m"
	lime    = "\033[38;5;118m"
	gray    = "\033[38;5;240m"
	purple  = "\033[38;5;141m"
)

func cc(color, text string) string { return color + text + reset }

// ─── Patterns ──────────────────────────────────────────────────────────────────
var (
	reJWT     = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
	reURL     = regexp.MustCompile(`https?://[a-zA-Z0-9._\-/:@%?=&#!,;~*()\[\]{}|^$+]+`)
	reEndpoint = regexp.MustCompile(`["` + "`" + `']((?:/(?:api|v\d+|graphql|rest|internal|admin|auth|oauth|user|users|account|accounts|token|tokens|login|logout|signin|signup|register|upload|download|config|settings|data|webhook|callback|refresh|profile|password|reset|verify|search|feed|post|comment|message|notification|payment|order|product|cart|checkout|session|dashboard|report|analytics|export|import|invite|team|workspace|org|organization|project|file|media|image|video|audio|document|permission|role|group|member|2fa|mfa|sso|saml|oidc|connect|public|private|v1|v2|v3|v4|v5)[a-zA-Z0-9_\-/:.?=&{}]*))["` + "`" + `']`)
	reSecret  = regexp.MustCompile(`(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key|client[_-]?secret|auth[_-]?token|password|passwd|api[_-]?secret|app[_-]?key|webhook[_-]?secret|signing[_-]?key|encryption[_-]?key|master[_-]?key)\s*[:=]\s*['"]?([A-Za-z0-9_\-\.+/]{8,})['"]?`)
	reEmail   = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reIP      = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	reToken   = regexp.MustCompile(`(?i)(?:bearer|access_token|refresh_token|id_token)\s*[:=]\s*['"]?([A-Za-z0-9_\-\.]{20,})['"]?`)
	reAWSKey  = regexp.MustCompile(`(?:AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}`)
	rePrivKey = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)
	reGraphQL = regexp.MustCompile(`(?i)(?:query|mutation|subscription)\s+\w+\s*(?:\([^)]*\))?\s*\{`)
	reS3      = regexp.MustCompile(`(?i)(?:s3://|amazonaws\.com/)[a-zA-Z0-9.\-_/]+`)
	reJSFile  = regexp.MustCompile(`https?://[a-zA-Z0-9._\-/:%?=&#!]+\.js(?:[?#][^\s"'` + "`" + `]*)?`)
	reJSPath  = regexp.MustCompile(`['"]([^'"` + "`" + `\s]+\.js(?:\?[^'"` + "`" + `\s]*)?)['"]`)
	reComment = regexp.MustCompile(`//[^\n]*|/\*[\s\S]*?\*/`)
	reFetch   = regexp.MustCompile(`(?i)fetch\s*\(\s*['"]([^'"]+)['"]`)
	reAxios   = regexp.MustCompile(`(?i)axios\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]`)
	reXHR     = regexp.MustCompile(`(?i)\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]`)
	reSrcAttr = regexp.MustCompile(`src=["']([^"']+\.js[^"']*)["']`)
)

// ─── Results ───────────────────────────────────────────────────────────────────
type Finding struct {
	Type  string
	Value string
	Src   string
}

type Results struct {
	mu      sync.Mutex
	items   []Finding
	seen    map[string]bool
}

func NewResults() *Results { return &Results{seen: make(map[string]bool)} }

func (r *Results) Add(typ, val, src string) {
	val = strings.TrimSpace(val)
	if val == "" {
		return
	}
	key := typ + "|" + val
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen[key] {
		return
	}
	r.seen[key] = true
	r.items = append(r.items, Finding{typ, val, src})
}

func (r *Results) Get(typ string) []Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Finding
	for _, f := range r.items {
		if f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

func (r *Results) All() []Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Finding{}, r.items...)
}

// ─── HTTP ──────────────────────────────────────────────────────────────────────
func newClient(insecure bool, timeout int, follow bool) *http.Client {
	cl := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}},
	}
	if !follow {
		cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return cl
}

func doFetch(client *http.Client, method, rawURL, ua string, hdrs []string, body string) (*http.Response, []byte, time.Duration, error) {
	var br io.Reader
	if body != "" {
		br = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, br)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	for _, h := range hdrs {
		if p := strings.SplitN(h, ":", 2); len(p) == 2 {
			req.Header.Set(strings.TrimSpace(p[0]), strings.TrimSpace(p[1]))
		}
	}
	t := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, b, time.Since(t), err
}

// ─── Scanning ──────────────────────────────────────────────────────────────────
func scan(content, src string, res *Results) {
	for _, m := range reJWT.FindAllString(content, -1) { res.Add("JWT", m, src) }
	for _, m := range reAWSKey.FindAllString(content, -1) { res.Add("AWS_KEY", m, src) }
	for _, m := range rePrivKey.FindAllString(content, -1) { res.Add("PRIVKEY", m, src) }
	for _, m := range reSecret.FindAllString(content, -1) { res.Add("SECRET", m, src) }
	for _, m := range reToken.FindAllString(content, -1) { res.Add("TOKEN", m, src) }
	for _, m := range reURL.FindAllString(content, -1) { res.Add("URL", m, src) }
	for _, m := range reGraphQL.FindAllString(content, -1) { res.Add("GRAPHQL", strings.TrimSpace(m), src) }
	for _, m := range reS3.FindAllString(content, -1) { res.Add("S3", m, src) }
	for _, m := range reEmail.FindAllString(content, -1) { res.Add("EMAIL", m, src) }
	for _, m := range reIP.FindAllString(content, -1) {
		if !strings.HasPrefix(m, "0.") && m != "127.0.0.1" {
			res.Add("IP", m, src)
		}
	}
	for _, mm := range reEndpoint.FindAllStringSubmatch(content, -1) {
		if len(mm) > 1 { res.Add("ENDPOINT", mm[1], src) }
	}
	for _, mm := range reFetch.FindAllStringSubmatch(content, -1) {
		if len(mm) > 1 { res.Add("ENDPOINT", mm[1], src) }
	}
	for _, mm := range reAxios.FindAllStringSubmatch(content, -1) {
		if len(mm) > 1 { res.Add("ENDPOINT", mm[1], src) }
	}
	for _, mm := range reXHR.FindAllStringSubmatch(content, -1) {
		if len(mm) > 1 { res.Add("ENDPOINT", mm[1], src) }
	}
}

func scanHeaders(resp *http.Response, res *Results) {
	for k, vals := range resp.Header {
		kl := strings.ToLower(k)
		for _, v := range vals {
			switch kl {
			case "set-cookie":
				res.Add("COOKIE", v, "header")
			case "server", "x-powered-by", "x-generator", "x-runtime", "x-aspnet-version":
				res.Add("SERVER", k+": "+v, "header")
			case "access-control-allow-origin":
				if v == "*" {
					res.Add("CORS*", "access-control-allow-origin: * ← WILDCARD CORS!", "header")
				} else {
					res.Add("CORS", k+": "+v, "header")
				}
			case "location":
				res.Add("REDIRECT", v, "header")
			case "www-authenticate":
				res.Add("AUTH", k+": "+v, "header")
			case "authorization":
				res.Add("SECRET", k+": "+v, "header")
			case "hackers", "x-hackers", "x-bug-bounty":
				res.Add("BUGBOUNTY", k+": "+v, "header")
			}
			for _, m := range reJWT.FindAllString(v, -1) { res.Add("JWT", m, "header") }
		}
	}
}

// ─── JS Collector ──────────────────────────────────────────────────────────────
func collectJS(content, baseURL string) []string {
	seen := map[string]bool{}
	var files []string
	base, _ := url.Parse(baseURL)

	add := func(u string) {
		u = strings.Trim(u, `"'` + "`")
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		files = append(files, u)
	}

	for _, m := range reJSFile.FindAllString(content, -1) { add(m) }
	for _, mm := range reJSPath.FindAllStringSubmatch(content, -1) {
		if len(mm) < 2 { continue }
		p := mm[1]
		if strings.HasPrefix(p, "http") {
			add(p)
		} else if base != nil {
			if ref, err := url.Parse(p); err == nil {
				add(base.ResolveReference(ref).String())
			}
		}
	}
	for _, mm := range reSrcAttr.FindAllStringSubmatch(content, -1) {
		if len(mm) < 2 { continue }
		p := mm[1]
		if strings.HasPrefix(p, "http") {
			add(p)
		} else if base != nil {
			if ref, err := url.Parse(p); err == nil {
				add(base.ResolveReference(ref).String())
			}
		}
	}
	return files
}

// ─── API Tree ──────────────────────────────────────────────────────────────────
func buildTree(endpoints []Finding) {
	if len(endpoints) == 0 {
		fmt.Println(cc(dim, "    (no endpoints found)"))
		return
	}
	groups := map[string]map[string]bool{}
	for _, e := range endpoints {
		parts := strings.SplitN(strings.TrimPrefix(e.Value, "/"), "/", 2)
		root := "/" + parts[0]
		if _, ok := groups[root]; !ok {
			groups[root] = map[string]bool{}
		}
		groups[root][e.Value] = true
	}
	roots := make([]string, 0, len(groups))
	for r := range groups { roots = append(roots, r) }
	sort.Strings(roots)

	for i, root := range roots {
		isLast := i == len(roots)-1
		pre := "├──"
		if isLast { pre = "└──" }
		fmt.Printf("  %s %s\n", cc(dim, pre), cc(bold+lime, root))

		children := make([]string, 0)
		for ch := range groups[root] { children = append(children, ch) }
		sort.Strings(children)

		for j, ch := range children {
			cp := "│   ├──"
			if j == len(children)-1 { cp = "│   └──" }
			if isLast { cp = strings.Replace(cp, "│", " ", 1) }
			if ch != root {
				fmt.Printf("  %s %s\n", cc(dim, cp), cc(lime, ch))
			}
		}
	}
}

// ─── Highlighters ──────────────────────────────────────────────────────────────
func hlStatus(line string) string {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 { return line }
	code := parts[1]
	msg := ""
	if len(parts) > 2 { msg = " " + parts[2] }
	var cl string
	switch {
	case strings.HasPrefix(code, "2"): cl = bold + green
	case strings.HasPrefix(code, "3"): cl = bold + yellow
	case strings.HasPrefix(code, "4"): cl = bold + orange
	case strings.HasPrefix(code, "5"): cl = bold + red
	default: cl = white
	}
	return cc(dim+white, parts[0]) + " " + cc(cl, code) + cc(dim, msg)
}

func hlHeader(line string) string {
	idx := strings.Index(line, ":")
	if idx < 0 { return line }
	key := strings.ToLower(strings.TrimSpace(line[:idx]))
	val := strings.TrimSpace(line[idx+1:])
	kc, vc := cyan, white
	switch key {
	case "set-cookie", "cookie": kc, vc = pink, pink
	case "server", "x-powered-by", "via", "x-generator", "x-runtime": kc, vc = orange, orange
	case "authorization", "x-api-key", "x-auth-token": kc, vc = red, red
	case "content-security-policy", "strict-transport-security", "x-frame-options",
		"x-xss-protection", "x-content-type-options", "referrer-policy": kc, vc = green, gray
	case "location": kc, vc = yellow, blue
	case "access-control-allow-origin":
		if val == "*" { kc, vc = bold+red, bold+red } else { kc, vc = yellow, yellow }
	case "www-authenticate": kc, vc = red, red
	case "hackers", "x-hackers", "x-bug-bounty": kc, vc = bold+lime, bold+lime
	}
	cv := cc(vc, val)
	cv = reJWT.ReplaceAllStringFunc(cv, func(m string) string { return cc(bold+cyan, m) })
	cv = reURL.ReplaceAllStringFunc(cv, func(m string) string { return cc(blue, m) })
	return cc(kc, line[:idx]) + ": " + cv
}

func hlBody(line string) string {
	r := line
	r = reJWT.ReplaceAllStringFunc(r, func(m string) string { return cc(bold+cyan, m) })
	r = reAWSKey.ReplaceAllStringFunc(r, func(m string) string { return cc(bold+red, m) })
	r = reSecret.ReplaceAllStringFunc(r, func(m string) string { return cc(bold+red, m) })
	r = reToken.ReplaceAllStringFunc(r, func(m string) string { return cc(yellow, m) })
	r = reURL.ReplaceAllStringFunc(r, func(m string) string { return cc(blue, m) })
	r = reEndpoint.ReplaceAllStringFunc(r, func(m string) string {
		mm := reEndpoint.FindStringSubmatch(m)
		if len(mm) > 1 { return strings.Replace(m, mm[1], cc(lime, mm[1]), 1) }
		return m
	})
	r = reEmail.ReplaceAllStringFunc(r, func(m string) string { return cc(magenta, m) })
	r = reIP.ReplaceAllStringFunc(r, func(m string) string {
		if strings.HasPrefix(m, "0.") { return m }
		return cc(orange, m)
	})
	r = reS3.ReplaceAllStringFunc(r, func(m string) string { return cc(purple, m) })
	r = reGraphQL.ReplaceAllStringFunc(r, func(m string) string { return cc(bold+yellow, m) })
	r = rePrivKey.ReplaceAllStringFunc(r, func(m string) string { return cc(bold+red, m) })
	return r
}

func hlJSON(data []byte) string {
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return hlBody(string(data))
	}
	b, _ := json.MarshalIndent(obj, "", "  ")
	s := string(b)
	s = regexp.MustCompile(`"([^"]+)":`).ReplaceAllStringFunc(s, func(m string) string {
		k := regexp.MustCompile(`"([^"]+)"`).FindString(m)
		return cc(pink, k) + ":"
	})
	s = regexp.MustCompile(`(?m):\s*"([^"]*)"(,?)$`).ReplaceAllStringFunc(s, func(m string) string {
		vm := regexp.MustCompile(`"([^"]*)"`).FindString(m)
		val := strings.Trim(vm, `"`)
		tail := ""
		if strings.HasSuffix(strings.TrimSpace(m), ",") { tail = "," }
		var col string
		switch {
		case reJWT.MatchString(val): col = cc(bold+cyan, `"`+val+`"`)
		case strings.HasPrefix(val, "http"): col = cc(blue, `"`+val+`"`)
		case reEmail.MatchString(val): col = cc(magenta, `"`+val+`"`)
		case len(val) > 20: col = cc(yellow, `"`+val+`"`)
		default: col = cc(lime, `"`+val+`"`)
		}
		return ": " + col + tail
	})
	s = regexp.MustCompile(`(?m):\s*(\d+\.?\d*)(,?)$`).ReplaceAllStringFunc(s, func(m string) string {
		return regexp.MustCompile(`\d+\.?\d*`).ReplaceAllStringFunc(m, func(n string) string { return cc(yellow, n) })
	})
	s = regexp.MustCompile(`(?m):\s*(true|false|null)(,?)$`).ReplaceAllStringFunc(s, func(m string) string {
		return regexp.MustCompile(`true|false|null`).ReplaceAllStringFunc(m, func(b string) string { return cc(orange, b) })
	})
	return s
}

// ─── UI ────────────────────────────────────────────────────────────────────────
func sep(label string) {
	line := strings.Repeat("─", 52)
	fmt.Printf("\n%s %s %s\n\n", cc(dim, "┌"+line), cc(bold+yellow, "[ "+label+" ]"), cc(dim, line+"┐"))
}

func banner(u, method string) {
	fmt.Println()
	fmt.Println(cc(bold+lime, "  ▄▄▄   ▄▄·  ▄• ▄▌▄▄▄  ▄▄▌ "))
	fmt.Println(cc(bold+lime, "  ▀▄ █·▐█ ▌▪ █▪██▌▀▄ █·██•  "))
	fmt.Println(cc(bold+lime, "  ▐▀▀▄ ██ ▄▄ █▌▐█▌▐▀▀▄ ██▪  "))
	fmt.Println(cc(bold+lime, "  ▐█•█▌▐███▌ ▐█▄█▌▐█•█▌▐█▌▐▌"))
	fmt.Println(cc(bold+lime, "  .▀  ▀·▀▀▀   ▀▀▀ .▀  ▀.▀▀▀ "))
	fmt.Println(cc(gray, "  acurl v2.0 — recon intelligence"))
	fmt.Println()
	fmt.Printf("  %s %s %s\n\n", cc(dim, "►"), cc(bold+yellow, method), cc(bold+blue, u))
}

// ─── multiFlag ─────────────────────────────────────────────────────────────────
type multiFlag []string
func (m *multiFlag) String() string       { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error   { *m = append(*m, v); return nil }

// ─── Main ──────────────────────────────────────────────────────────────────────
func main() {
	var (
		showHeaders = flag.Bool("i", false, "Show response headers")
		method      = flag.String("X", "GET", "HTTP method")
		data        = flag.String("d", "", "Request body")
		userAgent   = flag.String("A", "acurl/2.0", "User-Agent")
		follow      = flag.Bool("L", false, "Follow redirects")
		insecure    = flag.Bool("k", false, "Skip TLS verify")
		timeout     = flag.Int("t", 30, "Timeout seconds")
		mapJS       = flag.Bool("map", false, "Auto-fetch & map all JS files")
		onlyF       = flag.Bool("F", false, "Findings only")
		outFile     = flag.String("o", "", "Save raw body to file")
		jsonOut     = flag.Bool("json", false, "Findings as JSON")
		noBody      = flag.Bool("no-body", false, "Skip body output")
		threads     = flag.Int("T", 5, "JS fetch threads")
		verbose     = flag.Bool("v", false, "Verbose")
		headers     multiFlag
	)
	flag.Var(&headers, "H", "Custom header (repeatable)")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, cc(bold+red, "\nUsage: acurl [options] <URL>\n"))
		fmt.Fprintln(os.Stderr, "  -i              Show response headers")
		fmt.Fprintln(os.Stderr, "  -X METHOD       HTTP method (default: GET)")
		fmt.Fprintln(os.Stderr, "  -H HEADER       Custom header (repeatable)")
		fmt.Fprintln(os.Stderr, "  -d DATA         Request body")
		fmt.Fprintln(os.Stderr, "  -A AGENT        User-Agent")
		fmt.Fprintln(os.Stderr, "  -L              Follow redirects")
		fmt.Fprintln(os.Stderr, "  -k              Skip TLS verify")
		fmt.Fprintln(os.Stderr, "  -t SECS         Timeout (default: 30)")
		fmt.Fprintln(os.Stderr, "  --map           Fetch & map all JS files")
		fmt.Fprintln(os.Stderr, "  -F              Findings summary only")
		fmt.Fprintln(os.Stderr, "  --json          Output findings as JSON")
		fmt.Fprintln(os.Stderr, "  --no-body       Skip body output")
		fmt.Fprintln(os.Stderr, "  -T N            JS threads (default: 5)")
		fmt.Fprintln(os.Stderr, "  -o FILE         Save body to file")
		fmt.Fprintln(os.Stderr, "  -v              Verbose\n")
		fmt.Fprintln(os.Stderr, cc(yellow, "Examples:"))
		fmt.Fprintln(os.Stderr, "  acurl -i https://api.target.com/v1/users")
		fmt.Fprintln(os.Stderr, "  acurl -i --map https://target.com")
		fmt.Fprintln(os.Stderr, "  acurl -i -H 'Authorization: Bearer TOKEN' https://api.target.com")
		fmt.Fprintln(os.Stderr, "  acurl -F --json https://api.target.com > findings.json")
		os.Exit(1)
	}

	targetURL := args[0]
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}
	client := newClient(*insecure, *timeout, *follow)
	res := NewResults()

	banner(targetURL, *method)

	// Main request
	resp, body, elapsed, err := doFetch(client, *method, targetURL, *userAgent, headers, *data)
	if err != nil {
		fmt.Fprintf(os.Stderr, cc(bold+red, "\n  [ERROR] ")+cc(red, err.Error()+"\n\n"))
		os.Exit(1)
	}

	bodyStr := string(body)
	ct := resp.Header.Get("Content-Type")
	isJSON := strings.Contains(ct, "json")

	fmt.Printf("  %s %s   %s %s   %s %s   %s %s\n",
		cc(dim, "time:"), cc(white, elapsed.Round(time.Millisecond).String()),
		cc(dim, "size:"), cc(white, fmt.Sprintf("%d bytes", len(body))),
		cc(dim, "type:"), cc(white, ct),
		cc(dim, "proto:"), cc(white, resp.Proto),
	)

	scanHeaders(resp, res)
	scan(bodyStr, targetURL, res)

	if !*onlyF {
		sep("RESPONSE")
		fmt.Println("  " + hlStatus(fmt.Sprintf("%s %d %s", resp.Proto, resp.StatusCode, http.StatusText(resp.StatusCode))))

		if *showHeaders {
			sep("HEADERS")
			for k, vals := range resp.Header {
				for _, v := range vals {
					fmt.Println("  " + hlHeader(k+": "+v))
				}
			}
		}

		if !*noBody {
			sep("BODY")
			if isJSON {
				fmt.Println(hlJSON(body))
			} else {
				for _, line := range strings.Split(bodyStr, "\n") {
					fmt.Println(hlBody(line))
				}
			}
		}
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, body, 0644); err != nil {
			fmt.Fprintf(os.Stderr, cc(red, "Save error: "+err.Error()+"\n"))
		} else {
			fmt.Printf("\n  %s %s\n", cc(dim, "saved →"), cc(lime, *outFile))
		}
	}

	// JS Mapping
	if *mapJS {
		jsFiles := collectJS(bodyStr, targetURL)
		if len(jsFiles) == 0 {
			fmt.Println(cc(dim, "\n  [no JS files found]"))
		} else {
			sep(fmt.Sprintf("JS MAPPING — %d files", len(jsFiles)))
			for _, f := range jsFiles {
				fmt.Printf("  %s %s\n", cc(dim, "▸"), cc(blue, f))
			}

			sem := make(chan struct{}, *threads)
			var wg sync.WaitGroup
			for _, jsURL := range jsFiles {
				wg.Add(1)
				go func(u string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					_, jsBody, _, err := doFetch(client, "GET", u, *userAgent, headers, "")
					if err != nil {
						if *verbose { fmt.Printf("  %s %s\n", cc(red, "✗"), cc(dim, u)) }
						return
					}
					clean := reComment.ReplaceAllString(string(jsBody), " ")
					scan(clean, u, res)
					if *verbose { fmt.Printf("  %s %s\n", cc(lime, "✓"), cc(dim, u)) }
				}(jsURL)
			}
			wg.Wait()
		}
	}

	// API Tree
	endpoints := res.Get("ENDPOINT")
	if len(endpoints) > 0 {
		sep(fmt.Sprintf("API STRUCTURE — %d endpoints", len(endpoints)))
		buildTree(endpoints)
	}

	// Findings
	if *jsonOut {
		out := map[string][]string{}
		for _, f := range res.All() { out[f.Type] = append(out[f.Type], f.Value) }
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}

	order := []string{"JWT", "AWS_KEY", "PRIVKEY", "SECRET", "TOKEN", "CORS*", "CORS", "AUTH", "BUGBOUNTY", "COOKIE", "SERVER", "REDIRECT", "GRAPHQL", "S3", "URL", "ENDPOINT", "EMAIL", "IP", "VERSION"}
	colors := map[string]string{
		"JWT": cyan, "AWS_KEY": bold + red, "PRIVKEY": bold + red,
		"SECRET": red, "TOKEN": yellow, "CORS*": bold + red, "CORS": yellow,
		"AUTH": orange, "BUGBOUNTY": bold + lime, "COOKIE": pink,
		"SERVER": orange, "REDIRECT": blue, "GRAPHQL": bold + yellow,
		"S3": purple, "URL": blue, "ENDPOINT": lime,
		"EMAIL": magenta, "IP": orange, "VERSION": gray,
	}

	sep("FINDINGS SUMMARY")
	total := 0
	for _, typ := range order {
		items := res.Get(typ)
		if len(items) == 0 { continue }
		clr := colors[typ]
		fmt.Printf("  %s %s\n", cc(bold+clr, fmt.Sprintf("[%-8s]", typ)), cc(dim, fmt.Sprintf("%d found", len(items))))
		for _, f := range items {
			display := f.Value
			if len(display) > 130 { display = display[:130] + "..." }
			src := ""
			if f.Src != targetURL && f.Src != "header" && f.Src != "" {
				src = cc(gray, " ← "+f.Src)
			}
			fmt.Printf("    %s %s%s\n", cc(dim, "→"), cc(clr, display), src)
		}
		total += len(items)
		fmt.Println()
	}
	fmt.Printf("  %s %s\n\n", cc(dim, "total:"), cc(bold+lime, fmt.Sprintf("%d findings", total)))
}

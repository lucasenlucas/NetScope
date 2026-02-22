package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func runWebAnalysis(o options) {
	domain := normalizeDomain(o.domain)
	if !o.jsonOut {
		fmt.Printf("[*] Starting Web Analysis for target: %s\n", domain)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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

		req.Header.Set("User-Agent", "NetScope-Analysis/1.0")
		resp, err := clientWithRedirects.Do(req)
		if err != nil {
			req, _ = http.NewRequest("GET", "http://"+domain, nil)
			resp, err = clientWithRedirects.Do(req)
		}
		return resp, redirects, err
	}

	var resp *http.Response
	var reqErr error
	if o.httpCheck || o.tlsCheck || o.headersCheck || o.cacheCheck || o.fingerCheck {
		resp, _, reqErr = doReq()
	}

	if o.httpCheck {
		if reqErr != nil {
			fmt.Printf("[!] HTTP Error: %v\n", reqErr)
		} else {
			if !o.jsonOut {
				fmt.Printf("[+] Final URL: %s (Status: %d)\n", resp.Request.URL.String(), resp.StatusCode)
			}
		}
	}

	if o.tlsCheck {
		if resp != nil && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			if !o.jsonOut {
				fmt.Printf("[+] TLS Cert Issuer: %s, Valid To: %v\n", cert.Issuer.CommonName, cert.NotAfter)
			}
		} else {
			if !o.jsonOut {
				fmt.Println("[!] No TLS connection or certificates found")
			}
		}
	}

	if o.headersCheck {
		if resp != nil && !o.jsonOut {
			fmt.Printf("[+] HSTS: %s\n", resp.Header.Get("Strict-Transport-Security"))
			fmt.Printf("[+] CSP: %s\n", resp.Header.Get("Content-Security-Policy"))
		}
	}

	// measure checking moved inside
	if o.measure {
		var latencies []int64
		successProbes := 0
		var server, poweredBy string

		for i := 0; i < o.probes; i++ {
			start := time.Now()
			req, _ := http.NewRequest("GET", "https://"+domain, nil)
			req.Header.Set("User-Agent", getRandomUserAgent())
			respMeasure, err := client.Do(req)
			if err != nil {
				req, _ = http.NewRequest("GET", "http://"+domain, nil)
				req.Header.Set("User-Agent", getRandomUserAgent())
				respMeasure, err = client.Do(req)
			}
			if err == nil {
				duration := time.Since(start)
				latencies = append(latencies, duration.Milliseconds())
				successProbes++
				if server == "" {
					server = respMeasure.Header.Get("Server")
					poweredBy = respMeasure.Header.Get("X-Powered-By")
				}
				io.Copy(io.Discard, respMeasure.Body)
				respMeasure.Body.Close()
			}
		}

		if !o.jsonOut {
			fmt.Printf("[*] Probes: %d/%d success\n", successProbes, o.probes)
			if successProbes > 0 {
				fmt.Printf("[*] Server Header: %s\n", server)
				fmt.Printf("[*] X-Powered-By: %s\n", poweredBy)
			}
		}
	}

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
		if !o.jsonOut {
			fmt.Printf("[+] Open Ports: %v\n", portsData)
		}
	}

	if o.techCheck && resp != nil {
		techList := []string{}
		serverHeader := resp.Header.Get("Server")
		if serverHeader != "" {
			if strings.Contains(strings.ToLower(serverHeader), "nginx") {
				techList = append(techList, "Nginx")
			}
			if strings.Contains(strings.ToLower(serverHeader), "apache") {
				techList = append(techList, "Apache")
			}
			if strings.Contains(strings.ToLower(serverHeader), "cloudflare") {
				techList = append(techList, "Cloudflare")
			}
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			bodyStr := strings.ToLower(string(bodyBytes))
			if strings.Contains(bodyStr, "wp-content") || strings.Contains(bodyStr, "wp-includes") {
				techList = append(techList, "WordPress")
			}
			if strings.Contains(bodyStr, "react") || strings.Contains(bodyStr, "_reactroot") {
				techList = append(techList, "React")
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		if !o.jsonOut && len(techList) > 0 {
			fmt.Printf("[+] Detected Tech: %s\n", strings.Join(techList, ", "))
		}
	}

	// Paths
	if o.pathsCheck {
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
				req.Header.Set("User-Agent", "NetScope-Analysis/1.0")
				res, err := clientPaths.Do(req)
				if err != nil {
					url = "http://" + domain + path
					req, _ = http.NewRequest("GET", url, nil)
					req.Header.Set("User-Agent", "NetScope-Analysis/1.0")
					res, err = clientPaths.Do(req)
				}
				if err == nil {
					mu.Lock()
					if res.StatusCode == 200 {
						fmt.Printf("[+] Interesting Path Discovered: %s (HTTP 200)\n", path)
					}
					mu.Unlock()
					io.Copy(io.Discard, res.Body)
					res.Body.Close()
				}
			}(p)
		}
		wg.Wait()
	}

	// CORS
	if o.corsCheck {
		clientCors := &http.Client{Timeout: 5 * time.Second}
		req, _ := http.NewRequest("OPTIONS", "https://"+domain, nil)
		req.Header.Set("Origin", "https://evil.netscope.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		res, err := clientCors.Do(req)
		if err == nil {
			corsHeader := res.Header.Get("Access-Control-Allow-Origin")
			if !o.jsonOut && corsHeader != "" {
				fmt.Printf("[+] CORS ACAO: %s\n", corsHeader)
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
	}

	// Crawler
	if o.crawlerCheck {
		aiBots := []string{"gptbot", "ccbot", "claude-web", "anthropic-ai", "perplexitybot", "bytespider"}
		aiBlocked := false
		blockedBots := []string{}

		clientRobots := &http.Client{Timeout: 5 * time.Second}
		res, err := clientRobots.Get("https://" + domain + "/robots.txt")
		if err == nil && res.StatusCode == 200 {
			bodyBytes, _ := io.ReadAll(res.Body)
			bodyStr := strings.ToLower(string(bodyBytes))

			for _, bot := range aiBots {
				if strings.Contains(bodyStr, "user-agent: "+bot) {
					aiBlocked = true
					blockedBots = append(blockedBots, bot)
				}
			}
			res.Body.Close()
		}

		if !o.jsonOut {
			fmt.Printf("[+] AI Crawlers Protections: %v (Found rules for: %s)\n", aiBlocked, strings.Join(blockedBots, ", "))
		}
	}

	// CookieCheck
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
		if !o.jsonOut && len(cookieData) > 0 {
			fmt.Printf("[+] Analysed %d cookies. Remember to ensure Secure/HttpOnly are True.\n", len(cookieData))
		}
	}

	if o.methodCheck {
		methodsAllowed := "GET, POST, HEAD, OPTIONS"
		clientOptions := &http.Client{Timeout: 5 * time.Second}
		req, _ := http.NewRequest("OPTIONS", "https://"+domain, nil)
		res, err := clientOptions.Do(req)

		if err == nil {
			if allowHeader := res.Header.Get("Allow"); allowHeader != "" {
				methodsAllowed = allowHeader
			} else if accessControl := res.Header.Get("Access-Control-Allow-Methods"); accessControl != "" {
				methodsAllowed = accessControl
			}
			res.Body.Close()
		}

		if !o.jsonOut {
			fmt.Printf("[+] Allowed HTTP Methods: %s\n", methodsAllowed)
		}
	}

	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
}

package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Mapping of wordlists to their GitHub raw URLs from SecLists
var wordlistMapping = map[string]string{
	"common":     "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
	"parameters": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
	"passwords":  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
}

func getWordlist(o options, listType string) ([]string, error) {
	if o.wordlist != "" {
		return readLines(o.wordlist)
	}

	url, ok := wordlistMapping[listType]
	if !ok {
		return nil, fmt.Errorf("unknown wordlist type: %s", listType)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	netscopeDir := filepath.Join(homeDir, ".netscope", "wordlists")
	err = os.MkdirAll(netscopeDir, 0755)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}

	fileName := filepath.Base(url)
	localPath := filepath.Join(netscopeDir, fileName)

	// Check if already downloaded
	if _, err := os.Stat(localPath); err == nil {
		if !o.jsonOut {
			fmt.Printf("[*] Opgehaald: Lokale cache van %s\n", fileName)
		}
		return readLines(localPath)
	}

	// Download from GitHub
	if !o.jsonOut {
		fmt.Printf("[*] Wordlist niet lokaal gevonden. Downloadt %s (eenmalig)...\n", fileName)
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to download wordlist, status: %d", resp.StatusCode)
	}

	out, err := os.Create(localPath)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return nil, err
	}

	return readLines(localPath)
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func runVulnAnalysis(o options) {
	domain := normalizeDomain(o.domain)

	// Disable cert verification for vulnerability scans
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't auto-follow redirects for discovery
		},
	}

	workers := o.concurrency
	if workers <= 0 {
		workers = 10 // default for fuzzing
	}

	if o.dirCheck {
		if !o.jsonOut {
			fmt.Printf("\n[*] Start Directory & File Busting op %s...\n", domain)
		}

		words, err := getWordlist(o, "common")
		if err != nil {
			fmt.Printf("[!] Wordlist fout: %v\n", err)
		} else {
			runDirectoryBusting(client, domain, words, workers, o)
		}
	}

	if o.paramsCheck {
		if !o.jsonOut {
			fmt.Printf("\n[*] Start Parameter Discovery op %s...\n", domain)
		}
		words, err := getWordlist(o, "parameters")
		if err != nil {
			fmt.Printf("[!] Wordlist fout: %v\n", err)
		} else {
			runParameterDiscovery(client, domain, words, workers, o)
		}
	}

	if o.cmsCheck {
		if !o.jsonOut {
			fmt.Printf("\n[*] Start CMS Vulnerability & Footprint Scan op %s...\n", domain)
		}
		runCMSScan(client, domain, o)
	}

	if o.bruteCheck {
		if !o.jsonOut {
			fmt.Printf("\n[*] Start Credential Brute-Forcing op %s...\n", domain)
		}
		passwords, err := getWordlist(o, "passwords")
		if err != nil {
			fmt.Printf("[!] Wordlist fout: %v\n", err)
		} else {
			runCredentialBruteForce(client, domain, passwords, workers, o)
		}
	}
}

func getProtocol(client *http.Client, domain string) string {
	req, _ := http.NewRequest("GET", "https://"+domain, nil)
	_, err := client.Do(req)
	if err != nil {
		return "http://"
	}
	return "https://"
}

func runDirectoryBusting(client *http.Client, domain string, words []string, workers int, o options) {
	proto := getProtocol(client, domain)
	baselineURL := fmt.Sprintf("%s%s/netscope-random-%d", proto, domain, time.Now().UnixNano())
	req, _ := http.NewRequest("GET", baselineURL, nil)
	req.Header.Set("User-Agent", "NetScope/4.0")
	baselineResp, err := client.Do(req)

	baselineStatus := 404
	if err == nil {
		baselineStatus = baselineResp.StatusCode
		baselineResp.Body.Close()
	}

	if !o.jsonOut {
		fmt.Printf("[*] %d payloads geladen. Baseline 404 respons: HTTP %d\n", len(words), baselineStatus)
	}

	// 2. Setup Worker Pool
	urls := make(chan string, len(words))
	results := make(chan string, len(words))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range urls {
				if !strings.HasPrefix(path, "/") {
					path = "/" + path
				}
				target := fmt.Sprintf("%s%s%s", proto, domain, path)

				r, _ := http.NewRequest("GET", target, nil)
				r.Header.Set("User-Agent", "NetScope/4.0")
				res, err := client.Do(r)
				if err != nil {
					continue
				}

				status := res.StatusCode
				res.Body.Close()

				// Filter logic
				if status != 404 && status != baselineStatus {
					// We found something interesting
					results <- fmt.Sprintf("    - %s (HTTP %d)", path, status)
				}
			}
		}()
	}

	// 3. Feed workers
	for _, w := range words {
		urls <- w
	}
	close(urls)

	wg.Wait()
	close(results)

	// 4. Print results
	found := false
	for res := range results {
		if !found {
			if !o.jsonOut {
				fmt.Println("[+] Ontdekte mappen en bestanden:")
			}
			found = true
		}
		if !o.jsonOut {
			fmt.Println(res)
		}
	}

	if !found && !o.jsonOut {
		fmt.Println("[-] Geen verborgen bestanden of mappen ontdekt (naast baseline).")
	}
}

func runParameterDiscovery(client *http.Client, domain string, words []string, workers int, o options) {
	proto := getProtocol(client, domain)
	baseURL := fmt.Sprintf("%s%s/", proto, domain)

	// Baseline Request (No params)
	req, _ := http.NewRequest("GET", baseURL, nil)
	req.Header.Set("User-Agent", "NetScope/4.0")
	baselineRes, err := client.Do(req)

	baselineLength := int64(0)
	baselineStatus := 404
	if err == nil {
		body, _ := io.ReadAll(baselineRes.Body)
		baselineLength = int64(len(body))
		baselineStatus = baselineRes.StatusCode
		baselineRes.Body.Close()
	}

	if !o.jsonOut {
		fmt.Printf("[*] Baseline lengte: %d bytes (HTTP %d)\n", baselineLength, baselineStatus)
	}

	urls := make(chan string, len(words))
	results := make(chan string, len(words))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for param := range urls {
				target := fmt.Sprintf("%s?%s=netscope12345", baseURL, param)
				r, _ := http.NewRequest("GET", target, nil)
				r.Header.Set("User-Agent", "NetScope/4.0")
				res, err := client.Do(r)
				if err != nil {
					continue
				}

				body, _ := io.ReadAll(res.Body)
				length := int64(len(body))
				status := res.StatusCode
				res.Body.Close()

				// If response size or status severely differs from baseline, it might be parsing the param
				lengthDiff := length - baselineLength
				if lengthDiff < 0 {
					lengthDiff = -lengthDiff
				}

				// Arbitrary threshold: if difference > 50 bytes or status changes
				if status != baselineStatus || lengthDiff > 50 {
					results <- fmt.Sprintf("    - Param gevonden: ?%s= (HTTP %d, Length: %d)", param, status, length)
				}
			}
		}()
	}

	for _, w := range words {
		urls <- w
	}
	close(urls)

	wg.Wait()
	close(results)

	found := false
	for res := range results {
		if !found && !o.jsonOut {
			fmt.Println("[+] Ontdekte verborgen parameters:")
			found = true
		}
		if !o.jsonOut {
			fmt.Println(res)
		}
	}

	if !found && !o.jsonOut {
		fmt.Println("[-] Geen werkende parameters ontdekt.")
	}
}

func runCMSScan(client *http.Client, domain string, o options) {
	// A simple scanner checking typical CMS endpoints
	cmsPaths := map[string][]string{
		"WordPress": {"/wp-login.php", "/xmlrpc.php", "/wp-admin/", "/wp-config.php.bak"},
		"Joomla":    {"/administrator/", "/joomla.xml"},
		"Drupal":    {"/core/CHANGELOG.txt", "/user/login"},
		"Magento":   {"/magento_version"},
	}

	proto := getProtocol(client, domain)
	foundAny := false
	for cms, paths := range cmsPaths {
		for _, path := range paths {
			url := fmt.Sprintf("%s%s%s", proto, domain, path)
			req, _ := http.NewRequest("HEAD", url, nil)
			req.Header.Set("User-Agent", "NetScope/4.0")
			res, err := client.Do(req)
			if err == nil {
				if res.StatusCode == 200 || res.StatusCode == 401 || res.StatusCode == 403 {
					if !o.jsonOut {
						fmt.Printf("[!] %s artifact gevonden: %s (HTTP %d)\n", cms, path, res.StatusCode)
					}
					foundAny = true
				}
				res.Body.Close()
			}
		}
	}

	if !foundAny && !o.jsonOut {
		fmt.Println("[-] Geen bekende CMS inlogportalen of kwetsbare paden gevonden.")
	}
}

func runCredentialBruteForce(client *http.Client, domain string, passwords []string, workers int, o options) {
	// Simple Basic Auth Brute Force for demonstration
	// Assumes standard HTTP Basic Auth is protecting the root '/' or '/admin'
	proto := getProtocol(client, domain)
	targetURL := fmt.Sprintf("%s%s/", proto, domain)

	// Check if auth is required
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", "NetScope/4.0")
	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("[-] Kan doelwit niet bereiken: %v\n", err)
		return
	}
	res.Body.Close()

	if res.StatusCode != 401 && res.StatusCode != 403 {
		targetURL = fmt.Sprintf("%s%s/admin", proto, domain)
		req, _ = http.NewRequest("GET", targetURL, nil)
		req.Header.Set("User-Agent", "NetScope/4.0")
		res, _ = client.Do(req)
		if res != nil {
			res.Body.Close()
		}
		if res == nil || (res.StatusCode != 401 && res.StatusCode != 403) {
			if !o.jsonOut {
				fmt.Println("[-] Geen standaard Basic Auth (401) gedetecteerd op / of /admin. Brute force afgebroken.")
			}
			return
		}
	}

	// Wait, we need an explicit Username. Usually 'admin'
	user := o.username
	if user == "" {
		user = "admin"
	}

	if !o.jsonOut {
		fmt.Printf("[*] Basic Auth gedetecteerd op %s. Start fuzzing (User: %s)...\n", targetURL, user)
	}

	passChan := make(chan string, len(passwords))
	results := make(chan string, 1) // Only need one successful hit
	var wg sync.WaitGroup
	var stopFlag bool // Primitive cancellation
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pass := range passChan {
				mu.Lock()
				shouldStop := stopFlag
				mu.Unlock()
				if shouldStop {
					continue
				}

				r, _ := http.NewRequest("GET", targetURL, nil)
				r.SetBasicAuth(user, pass)
				r.Header.Set("User-Agent", "NetScope/4.0")
				rs, err := client.Do(r)
				if err != nil {
					continue
				}

				status := rs.StatusCode
				rs.Body.Close()

				// 200/301/302 means we bypassed the 401
				if status != 401 && status != 403 {
					mu.Lock()
					if !stopFlag {
						stopFlag = true
						results <- fmt.Sprintf("[+] SUCCES! Geldige inlog: %s:%s (HTTP %d)", user, pass, status)
					}
					mu.Unlock()
				}
			}
		}()
	}

	for _, p := range passwords {
		passChan <- p
	}
	close(passChan)
	wg.Wait()
	close(results)

	hit := false
	for r := range results {
		fmt.Println("\n" + r)
		hit = true
	}

	if !hit && !o.jsonOut {
		fmt.Println("[-] Geen wachtwoord gevonden in dit woordenboek.")
	}
}

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

// WordlistMapping stays as mapping of wordlists to their GitHub raw URLs from SecLists
var WordlistMapping = map[string]string{
	"common":     "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
	"parameters": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
	"wp_fuzz":    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt",
}

func getWordlist(listType string) ([]string, error) {

	url, ok := WordlistMapping[listType]
	if !ok {
		return nil, fmt.Errorf("onbekende wordlist type: %s", listType)
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
		return readLines(localPath)
	}

	// Download from GitHub
	fmt.Printf("[*] Wordlist niet lokaal gevonden. Downloadt %s (eenmalig)...\n", fileName)

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
		Timeout:   10 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	workers := o.concurrency
	if workers <= 0 {
		workers = 20
	}

	isWordPress := false

	if o.dirCheck {
		if !o.jsonOut {
			fmt.Printf("\n[*] Start Directory & File Busting op %s...\n", domain)
		}

		words, err := getWordlist("common")
		if err == nil {
			runDirectoryBusting(client, domain, words, workers, o)
		}
	}

	if o.paramsCheck {
		if !o.jsonOut {
			fmt.Printf("\n[*] Start Parameter Discovery op %s...\n", domain)
		}
		words, err := getWordlist("parameters")
		if err == nil {
			runParameterDiscovery(client, domain, words, workers, o)
		}
	}

	if o.cmsCheck {
		if !o.jsonOut {
			fmt.Printf("\n[*] Start CMS Vulnerability & Footprint Scan op %s...\n", domain)
		}
		isWordPress = runCMSScan(client, domain, o)
	}

	if isWordPress || o.cmsCheck {
		words, err := getWordlist("wp_fuzz")
		if err != nil {
			if !o.jsonOut {
				fmt.Printf("[!] Sla WP Plugin Enumeration over: kon wordlist niet laden (%v)\n", err)
			}
		} else if len(words) > 0 {
			// One final check to be 100% sure it's WP
			proto := getProtocol(client, domain)
			wpURL := fmt.Sprintf("%s%s/wp-login.php", proto, domain)
			req, _ := http.NewRequest("GET", wpURL, nil)
			res, err := client.Do(req)
			if err == nil && (res.StatusCode == 200 || res.StatusCode == 302) {
				res.Body.Close()
				if !o.jsonOut {
					fmt.Printf("\n[*] WordPress gedetecteerd. Start Plugin Enumeration (%d plugins)...\n", len(words))
				}
				runWPPluginFuzz(client, domain, words, workers, o)
			}
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

	urls := make(chan string, len(words))
	results := make(chan string, workers)
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

				if status != 404 && status != baselineStatus {
					results <- fmt.Sprintf("    - %s (HTTP %d)", path, status)
				}
			}
		}()
	}

	go func() {
		for _, w := range words {
			urls <- w
		}
		close(urls)
	}()

	wg.Wait()
	close(results)

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
}

func runParameterDiscovery(client *http.Client, domain string, words []string, workers int, o options) {
	proto := getProtocol(client, domain)
	baseURL := fmt.Sprintf("%s%s/", proto, domain)

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
	results := make(chan string, workers)
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

				diff := length - baselineLength
				if diff < 0 {
					diff = -diff
				}
				if status != baselineStatus || diff > 50 {
					results <- fmt.Sprintf("    - Param gevonden: ?%s= (HTTP %d, Length: %d)", param, status, length)
				}
			}
		}()
	}

	go func() {
		for _, w := range words {
			urls <- w
		}
		close(urls)
	}()

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
}

func runCMSScan(client *http.Client, domain string, o options) bool {
	cmsPaths := map[string][]string{
		"WordPress": {"/wp-login.php", "/xmlrpc.php", "/wp-admin/", "/wp-config.php.bak"},
		"Joomla":    {"/administrator/", "/joomla.xml"},
		"Drupal":    {"/core/CHANGELOG.txt", "/user/login"},
		"Magento":   {"/magento_version"},
	}

	proto := getProtocol(client, domain)
	foundWP := false
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
					if cms == "WordPress" {
						foundWP = true
					}
				}
				res.Body.Close()
			}
		}
	}

	if !foundAny && !o.jsonOut {
		fmt.Println("[-] Geen bekende CMS inlogportalen gevonden.")
	}
	return foundWP
}

func runWPPluginFuzz(client *http.Client, domain string, words []string, workers int, o options) {
	proto := getProtocol(client, domain)
	found := make(chan string, workers)
	urls := make(chan string, len(words))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for plugin := range urls {
				url := fmt.Sprintf("%s%s/wp-content/plugins/%s/", proto, domain, plugin)
				req, _ := http.NewRequest("HEAD", url, nil)
				req.Header.Set("User-Agent", "NetScope/4.0")
				res, err := client.Do(req)
				if err == nil {
					if res.StatusCode == 200 || res.StatusCode == 403 {
						found <- fmt.Sprintf("    - Plugin gevonden: %s", plugin)
					}
					res.Body.Close()
				}
			}
		}()
	}

	go func() {
		for _, w := range words {
			urls <- w
		}
		close(urls)
	}()

	wg.Wait()
	close(found)

	any := false
	for f := range found {
		if !any && !o.jsonOut {
			fmt.Println("[+] Ontdekte WordPress Plugins:")
			any = true
		}
		if !o.jsonOut {
			fmt.Println(f)
		}
	}
}

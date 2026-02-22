package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

const version = "3.4.9"

type scanOptions struct {
	domainFlag  string
	domainLong  string
	doScan      bool
	format      string
	outputDir   string
	timeoutSecs int
	noColor     bool
	quiet       bool
	showRaw     bool
	riskLevel   string
	subcheck    bool
	genMD       bool
}

type scanMeta struct {
	Domain     string    `json:"domain"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Version    string    `json:"lucaskit_version"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	RunID      string    `json:"run_id"`
}

type finding struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Severity          string   `json:"severity"`
	Description       string   `json:"description"`
	Evidence          string   `json:"evidence"`
	ReproductionSteps []string `json:"reproduction_steps"`
	Recommendation    string   `json:"recommendation"`
}

func main() {
	var o scanOptions

	flag.StringVar(&o.domainFlag, "d", "", "Domein (bijv. example.com)")
	flag.StringVar(&o.domainLong, "domain", "", "Domein (alias voor -d)")
	flag.BoolVar(&o.doScan, "scan", false, "Voer een volledige Lucas Kit analyse uit (UltraDNS + SiteStress + HTTP/TLS analyse)")
	flag.StringVar(&o.format, "format", "pdf", "Rapport formaat: pdf|md|json (default: pdf)")
	flag.StringVar(&o.outputDir, "out", "reports", "Basismap voor rapport output (default: ./reports)")
	flag.StringVar(&o.outputDir, "o", "reports", "Alias voor --out")
	flag.IntVar(&o.timeoutSecs, "timeout", 25, "Timeout per netwerkstap in seconden")
	flag.BoolVar(&o.noColor, "no-color", false, "Schakel kleuren uit (gereserveerd, huidige output gebruikt geen kleur)")
	flag.BoolVar(&o.quiet, "quiet", false, "Onderdruk alle runtime output behalve fouten en eindresultaat")
	flag.BoolVar(&o.showRaw, "show-raw", false, "Neem volledige command-output op in de PDF appendix")
	flag.StringVar(&o.riskLevel, "risk-level", "normal", "Risk-level voor analyse: strict|normal")
	flag.BoolVar(&o.subcheck, "subcheck", false, "Doe een lichte check op veelvoorkomende subdomeinen (www, api, mail)")
	flag.BoolVar(&o.genMD, "md", false, "Genereer een extra copy-paste Vriendelijk Markdown (.md) rapport")

	showHelp := flag.Bool("help", false, "Toon Lucas Kit help (inclusief UltraDNS & SiteStress)")
	showHelpShort := flag.Bool("h", false, "Toon help (kort)")
	showVersion := flag.Bool("version", false, "Toon versie van lucaskit")

	flag.Usage = func() {
		printHelp()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("lucaskit versie %s\n", version)
		os.Exit(0)
	}
	if *showHelp || *showHelpShort {
		printHelp()
		os.Exit(0)
	}

	// Kies domein uit -d of --domain
	domain := o.domainFlag
	if domain == "" {
		domain = o.domainLong
	}
	if domain == "" || !o.doScan {
		printHelp()
		os.Exit(2)
	}

	domain = normalizeDomain(domain)
	if domain == "" {
		fmt.Println("[!] Ongeldig domein.")
		os.Exit(2)
	}

	if o.outputDir == "" {
		o.outputDir = "reports"
	}

	start := time.Now()
	runID := start.Format("20060102_150405")
	baseDir := filepath.Join(o.outputDir, sanitizeFilename(domain), runID)
	rawDir := filepath.Join(baseDir, "raw")

	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		fmt.Printf("[!] Kon output map niet maken: %v\n", err)
		os.Exit(1)
	}

	commandsLogPath := filepath.Join(baseDir, "commands.log")
	cmdLog, err := os.Create(commandsLogPath)
	if err != nil {
		fmt.Printf("[!] Kon commands log niet openen: %v\n", err)
		os.Exit(1)
	}
	defer cmdLog.Close()

	steps := []string{
		"Target normaliseren & metadata",
		"DNS en mail security (UltraDNS)",
		"Subdomeinen & WHOIS (UltraDNS)",
		"HTTP(S) headers & reachability",
		"SiteStress measure (geen aanval)",
		"Rapport genereren",
	}

	progress := newProgressBar(len(steps), o.quiet)

	var findings []finding
	var rawData = make(map[string]interface{})

	methodology := "### Methodology & Commands\n\nAlle stappen zijn reproduceerbaar met de volgende handmatige commands:\n\n"

	// STEP 1: metadata
	progress.Step(1, steps[0])
	meta := scanMeta{
		Domain:    domain,
		StartedAt: start,
		Version:   version,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		RunID:     runID,
	}

	// STEP 2: UltraDNS basisinfo (-inf -n --json)
	progress.Step(2, steps[1])
	cmdUltra := []string{"ultradns", "-d", domain, "-inf", "-n", "--dnssec", "--json"}
	methodology += "- `" + strings.Join(cmdUltra, " ") + "`\n"

	ultraOut, _ := runCommandCaptureOutput(cmdUltra, filepath.Join(rawDir, "dns.json"), cmdLog, progress)
	var ultraJson map[string]interface{}
	json.Unmarshal(ultraOut, &ultraJson)
	rawData["ultradns"] = ultraJson

	// STEP 3: UltraDNS subdomeinen + whois
	progress.Step(3, steps[2])
	cmdWhois := []string{"ultradns", "-d", domain, "-subs", "-whois", "--json"}
	methodology += "- `" + strings.Join(cmdWhois, " ") + "`\n"

	whoisOut, _ := runCommandCaptureOutput(cmdWhois, filepath.Join(rawDir, "whois_subs.json"), cmdLog, progress)
	var whoisJson map[string]interface{}
	json.Unmarshal(whoisOut, &whoisJson)
	rawData["ultradns_extra"] = whoisJson

	// STEP 4: HTTP+TLS+Headers+Ports+Paths+CORS+Cookies+Brute+Tech+Crawlers+Methods analyse
	progress.Step(4, steps[3])
	cmdHttp := []string{"sitestress", "-d", domain, "--http", "--tls", "--headers", "--cache", "--fingerprint", "--ports", "--paths", "--cors", "--cookies", "--brute", "--tech", "--crawlers", "--methods", "--json"}
	methodology += "- `" + strings.Join(cmdHttp, " ") + "`\n"

	httpOut, _ := runCommandCaptureOutput(cmdHttp, filepath.Join(rawDir, "http_tls_headers.json"), cmdLog, progress)
	var httpJson map[string]interface{}
	json.Unmarshal(httpOut, &httpJson)
	rawData["http_tls"] = httpJson

	// STEP 5: SiteStress measure
	progress.Step(5, steps[4])
	cmdMeasure := []string{"sitestress", "-d", domain, "-measure", "-probes", "3", "--json"}
	methodology += "- `" + strings.Join(cmdMeasure, " ") + "`\n"

	measureOut, _ := runCommandCaptureOutput(cmdMeasure, filepath.Join(rawDir, "sitestress_measure.json"), cmdLog, progress)
	var measureJson map[string]interface{}
	json.Unmarshal(measureOut, &measureJson)
	rawData["measure"] = measureJson

	// Run Findings Engine
	findings = runFindingsEngine(rawData, o.riskLevel, domain)

	// STEP 6: Rapport
	progress.Step(6, steps[5])

	// schrijf meta & findings json
	meta.FinishedAt = time.Now()
	if b, err := json.MarshalIndent(meta, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(baseDir, "meta.json"), b, 0o644)
	}
	if b, err := json.MarshalIndent(findings, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(baseDir, "findings.json"), b, 0o644)
	}

	reportPath, err := writeReportPDF(baseDir, domain, rawData, methodology, findings, o.showRaw)
	if err != nil {
		if !o.quiet {
			fmt.Printf("\n[%s] [!] Kon PDF rapport niet opslaan: %v\n", now(), err)
		}
		os.Exit(1)
	}

	progress.Finish()
	if !o.quiet {
		fmt.Printf("\n[+] PDF Rapport gegenereerd: %s\n", reportPath)
	}

	if o.genMD {
		mdPath, mderr := writeReportMD(baseDir, domain, rawData, methodology, findings, o.showRaw)
		if mderr != nil {
			if !o.quiet {
				fmt.Printf("[!] Markdown generatie mislukt: %v\n", mderr)
			}
		} else if !o.quiet {
			fmt.Printf("[+] Markdown Rapport gegenereerd: %s\n", mdPath)
		}
	}
}

// normalizeDomain verwijdert protocol en trailing slashes/punt.
func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimSuffix(d, "/")
	d = strings.TrimSuffix(d, ".")
	return d
}

func now() string {
	return time.Now().Format(time.TimeOnly)
}

// progressBar is een simpele tekst progress bar.
type progressBar struct {
	total int
	quiet bool
}

func newProgressBar(total int, quiet bool) *progressBar {
	return &progressBar{total: total, quiet: quiet}
}

func (p *progressBar) Step(current int, label string) {
	if p.total <= 0 {
		return
	}
	if p.quiet {
		return
	}
	percent := int(float64(current) / float64(p.total) * 100)
	if percent > 100 {
		percent = 100
	}
	barWidth := 30
	filled := barWidth * percent / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Printf("\r[%s] [%s] %3d%% - %s\n", now(), bar, percent, label)
}

func (p *progressBar) LogMsg(msg string) {
	if p.quiet {
		return
	}
	fmt.Printf("%s\n", msg)
}

func (p *progressBar) Finish() {
	if p.quiet {
		return
	}
	fmt.Printf("\n")
}

func runCommandCaptureOutput(args []string, rawPath string, log io.Writer, p *progressBar) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("geen command")
	}

	start := time.Now()
	cmdStr := strings.Join(args, " ")
	if log != nil {
		fmt.Fprintf(log, "[%s] START %s\n", start.Format(time.RFC3339), cmdStr)
	}
	p.LogMsg(fmt.Sprintf("%s running: %s", now(), cmdStr))

	cmd := exec.Command(args[0], args[1:]...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard // Assuming submodules send clean JSON to stdout

	err := cmd.Run()

	combined := out.Bytes()

	if rawPath != "" {
		_ = os.WriteFile(rawPath, combined, 0o644)
	}

	end := time.Now()
	if log != nil {
		status := "OK"
		if err != nil {
			status = "ERR"
		}
		fmt.Fprintf(log, "[%s] DONE (%s) %s\n", end.Format(time.RFC3339), status, cmdStr)
	}

	return combined, err
}

// runFindingsEngine converts raw JSON data into structured findings.
func runFindingsEngine(data map[string]interface{}, riskLevel, domain string) []finding {
	var out []finding

	httpMap, _ := data["http_tls"].(map[string]interface{})
	httpData, _ := httpMap["http"].(map[string]interface{})
	tlsData, _ := httpMap["tls"].(map[string]interface{})
	headersData, _ := httpMap["headers"].(map[string]interface{})

	finalUrl, _ := httpData["final_url"].(string)

	// 1. Missing HTTPS
	if finalUrl != "" && !strings.HasPrefix(finalUrl, "https://") {
		out = append(out, finding{
			ID: "no_https", Title: "Geen HTTPS", Severity: "high",
			Description:       "De site gebruikt HTTP in plaats van beveiligde HTTPS.",
			Evidence:          fmt.Sprintf("Final URL: %s", finalUrl),
			ReproductionSteps: []string{fmt.Sprintf("sitestress -d %s --http --json", domain)},
			Recommendation:    "Implementeer TLS certificaten en stuur al het HTTP verkeer door naar HTTPS.",
		})
	}

	// 2. TLS Issues
	if tlsData != nil {
		if errStr, ok := tlsData["error"].(string); ok && errStr != "" {
			out = append(out, finding{
				ID: "tls_error", Title: "TLS Certificaat Fout", Severity: "high",
				Description: "Kan geen geldige TLS-verbinding opbouwen.", Evidence: errStr,
				ReproductionSteps: []string{fmt.Sprintf("sitestress -d %s --tls --json", domain)},
				Recommendation:    "Herstel de TLS configuratie of vervang het certificaat.",
			})
		} else if daysRemaining, ok := tlsData["days_remaining"].(float64); ok && daysRemaining < 14 {
			out = append(out, finding{
				ID: "tls_expiring", Title: "TLS Certificaat verloopt binnenkort", Severity: "medium",
				Description: "Het certificaat is geldig voor minder dan 14 dagen.", Evidence: fmt.Sprintf("Dagen resterend: %.0f", daysRemaining),
				ReproductionSteps: []string{fmt.Sprintf("sitestress -d %s --tls --json", domain)},
				Recommendation:    "Vernieuw het TLS certificaat zo snel mogelijk.",
			})
		}
	}

	// 3. Missing HSTS / CSP
	if headersData != nil {
		hsts, _ := headersData["hsts"].(string)
		if hsts == "" {
			out = append(out, finding{
				ID: "no_hsts", Title: "HSTS ontbreekt", Severity: "medium",
				Description: "Strict-Transport-Security header is niet ingesteld.", Evidence: "HSTS: MISSING",
				ReproductionSteps: []string{fmt.Sprintf("sitestress -d %s --headers --json", domain)},
				Recommendation:    "Configureer HSTS op de webserver om HTTPS af te dwingen.",
			})
		}

		csp, _ := headersData["csp"].(string)
		if csp == "" {
			out = append(out, finding{
				ID: "no_csp", Title: "CSP ontbreekt", Severity: "medium",
				Description: "Content-Security-Policy header is niet ingesteld.", Evidence: "CSP: MISSING",
				ReproductionSteps: []string{fmt.Sprintf("sitestress -d %s --headers --json", domain)},
				Recommendation:    "Stel een CSP in om XSS-aanvallen te mitigeren.",
			})
		}
	}

	// 4. DNS / Mail Security
	dnsMap, _ := data["ultradns"].(map[string]interface{})
	mailRaw, _ := dnsMap["mail"].(map[string]interface{})
	if mailRaw != nil {
		dmarc, _ := mailRaw["DMARC"].(string)
		if dmarc == "" {
			severity := "low"
			if riskLevel == "strict" {
				severity = "medium"
			}
			out = append(out, finding{
				ID: "no_dmarc", Title: "DMARC record ontbreekt", Severity: severity,
				Description: "Er is geen DMARC policy ingesteld voor e-mail.", Evidence: "DMARC: MISSING",
				ReproductionSteps: []string{fmt.Sprintf("ultradns -d %s -inf --json", domain)},
				Recommendation:    "Stel een DMARC record in op _dmarc." + domain + " met minimaal v=DMARC1; p=none;",
			})
		}
	}

	// 5. Ports Check
	if portsList, ok := httpMap["open_ports"].([]interface{}); ok && len(portsList) > 0 {
		var dangerousPorts []string
		var allOpenPorts []string
		for _, v := range portsList {
			portVal := fmt.Sprintf("%v", v)
			allOpenPorts = append(allOpenPorts, portVal)
			switch portVal {
			case "21", "22", "23", "25", "110", "143", "3306", "3389", "5432":
				dangerousPorts = append(dangerousPorts, portVal)
			}
		}
		if len(dangerousPorts) > 0 {
			out = append(out, finding{
				ID: "dangerous_ports", Title: "Gevaarlijke poorten blootgesteld", Severity: "high",
				Description:       "Er zijn direct toegankelijke beheer- of databasepoorten ontdekt via het publieke IP adres.",
				Evidence:          "Open ports: " + strings.Join(dangerousPorts, ", "),
				ReproductionSteps: []string{fmt.Sprintf("nmap -p21,22,23,25,110,143,3306,3389,5432 %s", domain)},
				Recommendation:    "Sluit deze poorten af via een firewall of beperk toegang uitsluitend tot vertrouwde (VPN) IPs.",
			})
		}
	}

	// 6. Paths Check
	if pathsData, ok := httpMap["paths"].(map[string]interface{}); ok {
		var exposedPaths []string
		for k, v := range pathsData {
			if vFloat, ok := v.(float64); ok && vFloat == 200 {
				exposedPaths = append(exposedPaths, k)
				// specifically catch dangerous ones
				if k == "/.git/config" || k == "/.env" || k == "/.well-known/security.txt" {
					sev := "high"
					if k == "/.well-known/security.txt" {
						sev = "info"
					}
					out = append(out, finding{
						ID: "exposed_path_" + k, Title: "Interessant Pad Ontdekt (" + k + ")", Severity: sev,
						Description:       "Er is een pad gedetecteerd dat mogelijk configuratie of gevoelige data prijsgeeft.",
						Evidence:          "HTTP 200 OK op " + k,
						ReproductionSteps: []string{fmt.Sprintf("curl -I https://%s%s", domain, k)},
						Recommendation:    "Evalueer of dit pad publiek toegankelijk hoort te zijn. Blokkeer zonodig aan de edge-kant.",
					})
				}
			}
		}
	}

	// 7. CORS
	if corsData, ok := httpMap["cors"].(map[string]interface{}); ok {
		origin := fmt.Sprintf("%v", corsData["allow_origin"])
		if origin == "*" || strings.Contains(origin, "evil.lucaskit.com") {
			out = append(out, finding{
				Title:          "Overmatig Permissieve CORS Configuratie",
				Severity:       "high",
				Description:    "De site retourneert actieve Access-Control-Allow-Origin headers die mogelijk (willekeurige) externe domeinen toestaan data op te halen.",
				Evidence:       fmt.Sprintf("Origin parameter ingesteld op ACAO: %s", origin),
				Recommendation: "Stel de CORS Access-Control-Allow-Origin strikt in op de verwachte interne en partner-domeinen, i.p.v. wildcards.",
			})
		}
	}

	// 8. Cookies
	if cookieList, ok := httpMap["cookies"].([]interface{}); ok {
		var insecureCookies []string
		for _, co := range cookieList {
			coMap, _ := co.(map[string]interface{})
			name := fmt.Sprintf("%v", coMap["name"])
			sec, _ := coMap["secure"].(bool)
			httponly, _ := coMap["httponly"].(bool)
			if !sec || !httponly {
				insecureCookies = append(insecureCookies, name)
			}
		}
		if len(insecureCookies) > 0 {
			out = append(out, finding{
				Title:          "Insecure Session Cookies",
				Severity:       "medium",
				Description:    "Er zijn actieve cookies ingesteld zonder de benodigde 'Secure' en/of 'HttpOnly' flags. Dit stelt de headers bloot aan Man-in-the-Middle en Cross-Site-Scripting (XSS) aanvallen.",
				Evidence:       "Kwetsbare cookies gedetecteerd: " + strings.Join(insecureCookies, ", "),
				Recommendation: "Voeg 'Secure' en 'HttpOnly' toe aan de backend response set-cookie parameters.",
			})
		}
	}

	// 9. Tech Detection
	if techMap, ok := httpMap["tech_stack"].(map[string]interface{}); ok {
		if detectList, ok := techMap["detected"].([]interface{}); ok && len(detectList) > 0 {
			var strTech []string
			for _, t := range detectList {
				strTech = append(strTech, fmt.Sprintf("%v", t))
			}
			out = append(out, finding{
				Title:          "Technologie & Frameworks Gedetecteerd",
				Severity:       "info",
				Description:    "Er zijn specifieke CMS systemen of web-technologieen herkend via HTML body of Headers.",
				Evidence:       "Detecies: " + strings.Join(strTech, ", "),
				Recommendation: "Zorg ervoor dat alle gedetecteerde componenten up-to-date zijn ivm CVE risicos.",
			})
		}
	}

	// 10. Bruteforce Fuzzing
	if bruteMap, ok := httpMap["bruteforce"].(map[string]interface{}); ok {
		if hits, ok := bruteMap["hits"].(map[string]interface{}); ok && len(hits) > 0 {
			var hitStr []string
			for k, v := range hits {
				hitStr = append(hitStr, fmt.Sprintf("%s (HTTP %v)", k, v))
			}
			out = append(out, finding{
				Title:          "Interessante Fuzzing Directories Gevonden",
				Severity:       "high",
				Description:    "Via directory bruteforcing is directe toegang tot administratieve backends of database gerelateerde paden vastgesteld.",
				Evidence:       "Positieve Fuzzing paden: " + strings.Join(hitStr, ", "),
				Recommendation: "Sluit deze paden direct af, minimaliseer error codes of verplaats authenticatie interfaces achter gesloten firewalls.",
			})
		}
	}

	// 11. AI Crawler Protections
	if crawlersMap, ok := httpMap["crawlers"].(map[string]interface{}); ok {
		protected, _ := crawlersMap["ai_protected"].(bool)
		if !protected {
			out = append(out, finding{
				Title:          "Geen AI Web-Crawler Beveiliging Gespot",
				Severity:       "info",
				Description:    "De site verbiedt LLM aggregators (zoals GPTBot, ClaudeBot, Perplexity) niet via robots.txt, waardoor interne open data gebruikt kan worden voor AI model training.",
				Evidence:       "Robots.txt mist specifieke Disallow regels voor bekende LLM user-agents.",
				Recommendation: "Indien data privacy en copyright extractie een zorg is, voeg LLM spiders toe aan robots.txt Disallow blokkades.",
			})
		}
	}

	// 12. HTTP Methods Allowed
	if methodsMap, ok := httpMap["http_methods"].(map[string]interface{}); ok {
		if allowed, ok := methodsMap["allowed"].(string); ok && allowed != "" {
			if strings.Contains(strings.ToUpper(allowed), "PUT") || strings.Contains(strings.ToUpper(allowed), "DELETE") || strings.Contains(strings.ToUpper(allowed), "TRACE") {
				out = append(out, finding{
					Title:          "Risicovolle HTTP Methods Ingeschakeld",
					Severity:       "medium",
					Description:    "De webserver accepteert verbindingen via potentieel destructieve HTTP methodes zoals PUT, DELETE of TRACE.",
					Evidence:       fmt.Sprintf("Allowed HTTP Methods header retourneert: %s", allowed),
					Recommendation: "Deactiveer DELETE, PUT, en TRACE op de load-balancer/webserver, en limiteer endpoints strikt tot GET, POST en OPTIONS.",
				})
			}
		}
	}

	return out
}

// writeReportPDF bouwt een uitgebreid PDF rapport (meerdere pagina's).
func writeReportPDF(dir, domain string, rawData map[string]interface{}, methodology string, findings []finding, includeRaw bool) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("lucaskit_report_%s_%s.pdf", sanitizeFilename(domain), timestamp)
	path := filepath.Join(dir, filename)

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("Lucas Kit – SiteStress / Analysis", false)
	pdf.SetAuthor("Lucas Kit", false)

	// Colors
	bgColorR, bgColorG, bgColorB := 239, 255, 246 // #effff6
	fgColorR, fgColorG, fgColorB := 50, 80, 70    // #325046
	lightGrR, lightGrG, lightGrB := 150, 180, 160 // Subtitle color

	var resolvedIP string
	if ipsRaw, ok := rawData["resolved_ips"].([]interface{}); ok && len(ipsRaw) > 0 {
		resolvedIP = fmt.Sprintf("%v", ipsRaw[0])
	} else {
		resolvedIP = "Onbekend"
	}

	var latencyStr, serverStr string
	if measureMap, ok := rawData["measure"].(map[string]interface{}); ok {
		if lats, ok := measureMap["latencies_ms"].([]interface{}); ok && len(lats) > 0 {
			if l, o := lats[0].(float64); o {
				latencyStr = fmt.Sprintf("%.0f ms", l)
			}
		}
		if srv, ok := measureMap["server"].(string); ok && srv != "" {
			serverStr = srv
		}
	}
	if latencyStr == "" {
		latencyStr = "Onbekend"
	}
	if serverStr == "" {
		serverStr = "Onbekend"
	}

	addPage := func(title string) {
		pdf.AddPage()
		pdf.SetFillColor(bgColorR, bgColorG, bgColorB)
		pdf.Rect(0, 0, 210, 297, "F") // Fill background
		pdf.SetTextColor(fgColorR, fgColorG, fgColorB)

		// Header Left
		pdf.SetXY(15, 20)
		pdf.SetFont("Helvetica", "B", 24)
		pdf.CellFormat(100, 10, "LUCAS", "", 1, "L", false, 0, "")
		pdf.SetXY(15, 30)
		pdf.CellFormat(100, 10, "KIT", "", 1, "L", false, 0, "")

		pdf.SetXY(15, 45)
		pdf.SetFont("Helvetica", "", 14)
		pdf.CellFormat(100, 8, "SITESTRESS / ANALYSIS / (v"+version+")", "", 1, "L", false, 0, "")

		pdf.SetXY(15, 53)
		pdf.SetTextColor(lightGrR, lightGrG, lightGrB)
		pdf.SetFont("Helvetica", "", 10)
		pdf.CellFormat(100, 6, time.Now().Format("02-01-2006")+" ("+domain+")", "", 1, "L", false, 0, "")

		pdf.SetTextColor(fgColorR, fgColorG, fgColorB)

		if title != "" {
			pdf.SetXY(15, 70)
			pdf.SetFont("Helvetica", "B", 14)
			pdf.CellFormat(100, 8, title, "", 1, "L", false, 0, "")
			pdf.SetXY(15, 85)
		}
	}

	addPage("")

	// Header Right (Algemene gegevens)
	pdf.SetXY(130, 20)
	pdf.SetFont("Helvetica", "", 11)
	pdf.CellFormat(70, 6, "Algemene gegevens van scan", "", 1, "L", false, 0, "")
	pdf.Ln(4)

	pdf.SetX(130)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(70, 5, "Domein:", "", 1, "L", false, 0, "")
	pdf.SetX(130)
	pdf.SetTextColor(lightGrR, lightGrG, lightGrB)
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(70, 5, domain, "", 1, "L", false, 0, "")
	pdf.Ln(3)

	pdf.SetX(130)
	pdf.SetTextColor(fgColorR, fgColorG, fgColorB)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(70, 5, "IP:", "", 1, "L", false, 0, "")
	pdf.SetX(130)
	pdf.SetTextColor(lightGrR, lightGrG, lightGrB)
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(70, 5, resolvedIP, "", 1, "L", false, 0, "")
	pdf.Ln(3)

	pdf.SetX(130)
	pdf.SetTextColor(fgColorR, fgColorG, fgColorB)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(70, 5, "Latency:", "", 1, "L", false, 0, "")
	pdf.SetX(130)
	pdf.SetTextColor(lightGrR, lightGrG, lightGrB)
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(70, 5, latencyStr, "", 1, "L", false, 0, "")
	pdf.Ln(3)

	pdf.SetX(130)
	pdf.SetTextColor(fgColorR, fgColorG, fgColorB)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(70, 5, "Server Header:", "", 1, "L", false, 0, "")
	pdf.SetX(130)
	pdf.SetTextColor(lightGrR, lightGrG, lightGrB)
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(70, 5, serverStr, "", 1, "L", false, 0, "")

	// Main Content Column (Left)
	pdf.SetTextColor(fgColorR, fgColorG, fgColorB)
	pdf.SetXY(15, 80)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(0, 8, cleanPDFText("Executive Summary"), "", 1, "L", false, 0, "")
	pdf.Ln(2)
	pdf.SetFont("Helvetica", "", 10)
	pdf.MultiCell(100, 5, cleanPDFText("In deze scan analyseert Lucas Kit het aangegeven doelwit op mogelijke blootstellingen en configuratiefouten. Binnen deze rapportage vindt u informatie over:\n- DNS/Mail Configuratie Beveiliging\n- HTTP Headers & Certificaat Validatie\n- DDoS Volumetrische Resistentie\n- Beheerders-poorten en datalek-paden."), "", "", false)
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(0, 8, cleanPDFText("Scope"), "", 1, "L", false, 0, "")
	pdf.Ln(2)
	pdf.SetFont("Helvetica", "", 10)
	scopeText := "- In scope: " + domain + " en geidentificeerde gerelateerde subdomeinen.\n- Out of scope: VPNs, Interne infrastructuren, Externe applicaties niet publiek georienteerd op dit domein."
	pdf.MultiCell(100, 5, cleanPDFText(scopeText), "", "", false)
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(0, 8, cleanPDFText("Methodologie"), "", 1, "L", false, 0, "")
	pdf.Ln(2)
	pdf.SetFont("Helvetica", "", 10)
	pdf.MultiCell(0, 5, cleanPDFText("Dit document is geunificeerd middels CLI tools (SiteStress & UltraDNS) en bevat exacte acties met timestamps. De onderliggende data is tevens als machine-leesbare JSON bestanden gegenereerd."), "", "", false)
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(0, 8, cleanPDFText("Tools & Environment"), "", 1, "L", false, 0, "")
	pdf.Ln(2)
	pdf.SetFont("Helvetica", "", 10)
	pdf.MultiCell(0, 5, cleanPDFText("- SiteStress "+version+"\n- ultradns "+version+"\n- macOS / Linux"), "", "", false)

	// PAGE 2: DNS & Mail
	addPage("DNS Configuratie & Mail Security")
	pdf.SetXY(15, 85)
	pdf.SetFont("Helvetica", "", 10)

	dnsMap, _ := rawData["ultradns"].(map[string]interface{})
	if dnsMap != nil {
		pdf.SetFont("Helvetica", "B", 12)
		pdf.CellFormat(0, 6, "Resolutie Data", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		records, _ := dnsMap["records"].(map[string]interface{})
		for t, val := range records {
			pdf.CellFormat(0, 5, fmt.Sprintf("%s Records:", t), "", 1, "L", false, 0, "")
			if arr, ok := val.([]interface{}); ok {
				for _, v := range arr {
					pdf.CellFormat(0, 5, fmt.Sprintf(" - %v", v), "", 1, "L", false, 0, "")
				}
			}
			pdf.Ln(2)
		}

		pdf.Ln(4)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.CellFormat(0, 6, "Mail Security (DMARC, SPF, DKIM)", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		mailRaw, _ := dnsMap["mail"].(map[string]interface{})
		for t, val := range mailRaw {
			vStr := fmt.Sprintf("%v", val)
			if vStr == "" {
				vStr = "Niet ingesteld"
			}
			pdf.CellFormat(0, 5, fmt.Sprintf("%s: %s", t, vStr), "", 1, "L", false, 0, "")
		}
	} else {
		pdf.MultiCell(0, 5, "Geen UltraDNS data beschikbaar in de JSON output.", "", "", false)
	}

	// PAGE 3: Extra Info (Ports, Paths, Cache)
	addPage("Port Scans & Path Discovery")
	pdf.SetXY(15, 85)

	httpMap, _ := rawData["http_tls"].(map[string]interface{})
	if httpMap != nil {
		pdf.SetFont("Helvetica", "B", 12)
		pdf.CellFormat(0, 6, "Open Poorten", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		if portsList, ok := httpMap["open_ports"].([]interface{}); ok && len(portsList) > 0 {
			var strPorts []string
			for _, p := range portsList {
				strPorts = append(strPorts, fmt.Sprintf("%v", p))
			}
			pdf.MultiCell(0, 5, "Geidentificeerde open poorten via TLS TCP connecties: "+strings.Join(strPorts, ", "), "", "", false)
		} else {
			pdf.MultiCell(0, 5, "Er zijn geen bekende open poorten ontdekt naast mogelijke verplichte web-poorten.", "", "", false)
		}

		pdf.Ln(6)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.CellFormat(0, 6, "Path HTTP Status Responses", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		if pathsData, ok := httpMap["paths"].(map[string]interface{}); ok {
			for path, status := range pathsData {
				pdf.CellFormat(0, 5, fmt.Sprintf("%s : HTTP %v", path, status), "", 1, "L", false, 0, "")
			}
		} else {
			pdf.MultiCell(0, 5, "Geen path discovery resultaten gevonden.", "", "", false)
		}
	} else {
		pdf.MultiCell(0, 5, "HTTP module data afwezig.", "", "", false)
	}

	// PAGE 4: Findings / Vulnerabilities
	addPage("Findings & Aanbevelingen")
	pdf.SetXY(15, 85)

	if len(findings) == 0 {
		pdf.MultiCell(0, 5, cleanPDFText("Uit alle verzamelde HTTP/DNS gegevens zijn geen directe kwetsbaarheden of configuratiefouten ontdekt. De infrastructuur lijkt stevig ingeregeld."), "", "", false)
	} else {
		for i, f := range findings {
			pdf.SetFont("Helvetica", "B", 12)
			pdf.CellFormat(0, 6, cleanPDFText(fmt.Sprintf("Finding #%d: %s", i+1, f.Title)), "", 1, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 10)

			pdf.SetTextColor(lightGrR, lightGrG, lightGrB)
			pdf.CellFormat(25, 5, cleanPDFText("Severity:"), "", 0, "L", false, 0, "")
			pdf.SetTextColor(fgColorR, fgColorG, fgColorB)
			pdf.SetFont("Helvetica", "B", 10)
			pdf.CellFormat(0, 5, cleanPDFText(strings.ToUpper(f.Severity)), "", 1, "L", false, 0, "")

			pdf.SetFont("Helvetica", "", 10)
			pdf.SetTextColor(lightGrR, lightGrG, lightGrB)
			pdf.CellFormat(0, 5, cleanPDFText("Description:"), "", 1, "L", false, 0, "")
			pdf.SetTextColor(fgColorR, fgColorG, fgColorB)
			pdf.MultiCell(0, 5, cleanPDFText(f.Description), "", "", false)

			pdf.SetTextColor(lightGrR, lightGrG, lightGrB)
			pdf.CellFormat(0, 5, cleanPDFText("Evidence:"), "", 1, "L", false, 0, "")
			pdf.SetTextColor(fgColorR, fgColorG, fgColorB)
			pdf.MultiCell(0, 5, cleanPDFText(f.Evidence), "", "", false)

			pdf.SetTextColor(lightGrR, lightGrG, lightGrB)
			pdf.CellFormat(0, 5, cleanPDFText("Recommendation:"), "", 1, "L", false, 0, "")
			pdf.SetTextColor(fgColorR, fgColorG, fgColorB)
			pdf.MultiCell(0, 5, cleanPDFText(f.Recommendation), "", "", false)

			pdf.Ln(4)
		}
	}

	pdf.Ln(8)
	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(0, 8, "Risk Rating Overzicht", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(80, 8, "Issue", "1", 0, "C", false, 0, "")
	pdf.CellFormat(40, 8, "Severity", "1", 0, "C", false, 0, "")
	pdf.CellFormat(40, 8, "Status", "1", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "", 10)
	if len(findings) == 0 {
		pdf.CellFormat(80, 8, "Geen Issues Opgemerkt", "1", 0, "L", false, 0, "")
		pdf.CellFormat(40, 8, "-", "1", 0, "C", false, 0, "")
		pdf.CellFormat(40, 8, "-", "1", 1, "C", false, 0, "")
	} else {
		for _, f := range findings {
			pdf.CellFormat(80, 8, f.Title, "1", 0, "L", false, 0, "")
			pdf.CellFormat(40, 8, strings.ToUpper(f.Severity), "1", 0, "C", false, 0, "")
			pdf.CellFormat(40, 8, "Open", "1", 1, "C", false, 0, "")
		}
	}

	// PAGE 5: Legal & Appendix
	addPage("Legal / Appendix")
	pdf.SetXY(15, 85)

	pdf.SetFont("Helvetica", "B", 12)
	pdf.CellFormat(0, 8, cleanPDFText("Legal Notice"), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	legalText := "Dit document en de scanresultaten zijn uitsluitend bestemd voor gebruik door bevoegde personen. " +
		"De Lucas Kit (ultradns / sitestress / lucaskit modules) en de auteur hiervan, Lucas Mangroelal, " +
		"getoetst te worden door een gediplomeerde pentester alvorens beslissingen worden doorgevoerd."
	pdf.MultiCell(0, 5, cleanPDFText(legalText), "", "", false)

	if includeRaw {
		pdf.Ln(8)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.CellFormat(0, 8, cleanPDFText("Appendix - Commands Timeline"), "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(0, 5, cleanPDFText(methodology), "", "", false)
		pdf.Ln(4)
		pdf.MultiCell(0, 5, cleanPDFText("Alle verzamelde data is in JSON formaat weggeschreven in de /reports directory per timestamp."), "", "", false)
	}

	if err := pdf.OutputFileAndClose(path); err != nil {
		return "", err
	}

	return path, nil
}

// writeReportMD bouwt een platte Markdown rapportage (optioneel via --md).
func writeReportMD(dir, domain string, rawData map[string]interface{}, methodology string, findings []finding, includeRaw bool) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("lucaskit_report_%s_%s.md", sanitizeFilename(domain), timestamp)
	path := filepath.Join(dir, filename)

	var b bytes.Buffer
	b.WriteString(fmt.Sprintf("# Lucas Kit - Analysis Report\n\n"))
	b.WriteString(fmt.Sprintf("**Domain:** `%s`\n", domain))
	b.WriteString(fmt.Sprintf("**Date:** %s\n", time.Now().Format("02-01-2006 15:04:05")))
	b.WriteString(fmt.Sprintf("**Tool Version:** v%s\n\n", version))
	b.WriteString("---\n\n")

	b.WriteString("## Executive Summary\n")
	b.WriteString("In deze scan analyseert Lucas Kit het aangegeven doelwit op mogelijke blootstellingen en configuratiefouten.\n\n")

	b.WriteString("## Findings & Aanbevelingen\n")
	if len(findings) == 0 {
		b.WriteString("Er zijn geen directe kwetsbaarheden gevonden. De huidige configuratie voldoet.\n\n")
	} else {
		for i, f := range findings {
			b.WriteString(fmt.Sprintf("### Finding #%d: %s\n", i+1, f.Title))
			b.WriteString(fmt.Sprintf("- **Severity:** `%s`\n", strings.ToUpper(f.Severity)))
			b.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Description))
			b.WriteString(fmt.Sprintf("- **Evidence:** %s\n", f.Evidence))
			b.WriteString(fmt.Sprintf("- **Recommendation:** %s\n\n", f.Recommendation))
		}
	}

	b.WriteString("## Appendix\n\n")
	b.WriteString("Genereert door Lucas Kit. Resultaten zijn indicaties voor management en tech-lead doeleinden.\n\n")
	if includeRaw {
		b.WriteString("### Commands Timeline\n\n")
		b.WriteString(methodology)
	}

	err := os.WriteFile(path, b.Bytes(), 0o644)
	return path, err
}

// cleanPDFText ensures any unicode smart quotes, bullets, or emojis are replaced with standard ASCII characters
// to prevent gofpdf cp1252 rendering glitches like 'â€¢'.
func cleanPDFText(s string) string {
	s = strings.ReplaceAll(s, "•", "-") // Replace bullets
	s = strings.ReplaceAll(s, "”", "\"")
	s = strings.ReplaceAll(s, "“", "\"")
	s = strings.ReplaceAll(s, "’", "'")
	s = strings.ReplaceAll(s, "‘", "'")
	s = strings.ReplaceAll(s, "–", "-") // En dash
	s = strings.ReplaceAll(s, "—", "-") // Em dash
	return s
}

func appendCommand(w *bytes.Buffer, args []string) {
	if len(args) == 0 {
		return
	}
	w.WriteString("- ")
	w.WriteString("`")
	w.WriteString(strings.Join(args, " "))
	w.WriteString("`")
	w.WriteString("\n")
}

func sanitizeFilename(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

func printHelp() {
	fmt.Println("Lucas Kit – Domain Toolkit (lucaskit)")
	fmt.Println()
	fmt.Println("Gebruik:")
	fmt.Println("  lucaskit -d <domein> -scan [--out ./reports] [--format pdf]")
	fmt.Println("  lucaskit --domain <domein> --scan")
	fmt.Println()
	fmt.Println("Beschrijving:")
	fmt.Println("  Voert een volledige analyse uit met UltraDNS, SiteStress (measure) en een HTTP security header check,")
	fmt.Println("  en genereert een professioneel PDF-rapport (meerdere pagina's) met alle outputs, verbeterpunten en gebruikte commands.")
	fmt.Println()
	fmt.Println("Belangrijkste opties:")
	fmt.Println("  -d, --domain <domein> : Doel-domein (bijv. example.com)")
	fmt.Println("  --scan               : Start de Lucas Kit scan workflow")
	fmt.Println("  --out, -o <map>      : Basismap waarin de rapportmap wordt opgeslagen (default: ./reports)")
	fmt.Println("  --format             : Formaat (nu vooral pdf; geplande: md/json)")
	fmt.Println("  --timeout <seconden> : Timeout per netwerkstap")
	fmt.Println("  --quiet              : Onderdruk runtime output (alleen eindresultaat)")
	fmt.Println("  --show-raw           : Neem ruwe command-output op in de PDF appendix")
	fmt.Println("  --risk-level         : Analyse strengheid: strict|normal")
	fmt.Println("  --help / -h          : Toon deze helptekst")
	fmt.Println("  --version            : Toon lucaskit versie")
	fmt.Println()
	fmt.Println("UltraDNS (ultradns) – DNS & Mail Security")
	fmt.Println("  ultradns -d <domein> -inf -n          # Alle DNS + mail checks")
	fmt.Println("  ultradns -d <domein> -whois           # WHOIS informatie")
	fmt.Println("  ultradns -d <domein> -subs            # Subdomeinen via Certificate Transparency")
	fmt.Println()
	fmt.Println("SiteStress (sitestress) – HTTP Stress / Load Testing")
	fmt.Println("  sitestress -measure -d <domein>       # Meet de sterkte en krijg een advies level")
	fmt.Println("  sitestress -d <domein> -t 10 -level 5 # Voorbeeld aanval (alleen met toestemming!)")
	fmt.Println()
	fmt.Println("Tip: lucaskit -d <domein> -scan combineert bovenstaande tools en schrijft alles weg in één rapport.")
}

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

const version = "3.4.4"

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
		fmt.Println("❌ Ongeldig domein.")
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
		fmt.Printf("❌ Kon output map niet maken: %v\n", err)
		os.Exit(1)
	}

	commandsLogPath := filepath.Join(baseDir, "commands.log")
	cmdLog, err := os.Create(commandsLogPath)
	if err != nil {
		fmt.Printf("❌ Kon commands log niet openen: %v\n", err)
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

	// Buffers voor het rapport
	var ultraPrimary bytes.Buffer
	var ultraExtra bytes.Buffer
	var httpInfo bytes.Buffer
	var sitestressMeasure bytes.Buffer
	var methodology bytes.Buffer
	var findings []finding

	methodology.WriteString("### Methodology & Commands\n\n")
	methodology.WriteString("Alle stappen zijn reproduceerbaar met de volgende handmatige commands:\n\n")

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

	// STEP 2: UltraDNS basisinfo (-inf -n)
	progress.Step(2, steps[1])
	cmd1 := []string{"ultradns", "-d", domain, "-inf", "-n"}
	appendCommand(&methodology, cmd1)
	_ = runCommandCapture(cmd1, &ultraPrimary, filepath.Join(rawDir, "dns.txt"), cmdLog)

	// STEP 3: UltraDNS subdomeinen + whois
	progress.Step(3, steps[2])
	cmd2 := []string{"ultradns", "-d", domain, "-subs", "-whois"}
	if o.subcheck {
		// lichte extra subdomein check kan later worden uitgebreid
	}
	appendCommand(&methodology, cmd2)
	_ = runCommandCapture(cmd2, &ultraExtra, filepath.Join(rawDir, "whois_subs.txt"), cmdLog)

	// STEP 4: HTTP header analyse
	progress.Step(4, steps[3])
	httpRes, httpErr := runHTTPAnalysis(domain, &httpInfo, time.Duration(o.timeoutSecs)*time.Second)
	if httpErr != nil {
		// Fout wordt in rapport vermeld; scan gaat door.
	}
	methodology.WriteString("- HTTP analyse: intern uitgevoerd via lucaskit (GET https://")
	methodology.WriteString(domain)
	methodology.WriteString(" met fallback naar http://")
	methodology.WriteString(domain)
	methodology.WriteString(")\n")
	if httpRes != nil {
		findings = append(findings, deriveHTTPFindings(*httpRes, o.riskLevel, domain)...)
	}

	// STEP 5: SiteStress measure
	progress.Step(5, steps[4])
	cmd4 := []string{"sitestress", "-measure", "-d", domain}
	appendCommand(&methodology, cmd4)
	_ = runCommandCapture(cmd4, &sitestressMeasure, filepath.Join(rawDir, "sitestress_measure.txt"), cmdLog)

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

	reportPath, err := writeReport(baseDir, domain, ultraPrimary.String(), ultraExtra.String(), httpInfo.String(), sitestressMeasure.String(), methodology.String(), findings, o.showRaw)
	if err != nil {
		if !o.quiet {
			fmt.Printf("\n[%s] ❌ Kon rapport niet opslaan: %v\n", now(), err)
		}
		os.Exit(1)
	}

	progress.Finish()
	if !o.quiet {
		fmt.Printf("\n✅ Rapport gegenereerd: %s\n", reportPath)
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
	fmt.Printf("\r[%s] [%s] %3d%% - %s", now(), bar, percent, label)
}

func (p *progressBar) Finish() {
	if p.quiet {
		return
	}
	fmt.Printf("\n")
}

// runCommandCapture voert een extern command uit, vangt alle output en schrijft
// naar buffer, raw-bestand en commands.log, zonder live output op stdout.
func runCommandCapture(args []string, buf *bytes.Buffer, rawPath string, log io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("geen command")
	}

	start := time.Now()
	if log != nil {
		fmt.Fprintf(log, "[%s] START %s\n", start.Format(time.RFC3339), strings.Join(args, " "))
	}

	cmd := exec.Command(args[0], args[1:]...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	var combined bytes.Buffer
	mw := io.MultiWriter(&combined, buf)

	go io.Copy(mw, stdout)
	go io.Copy(mw, stderr)

	err = cmd.Wait()

	if rawPath != "" {
		_ = os.WriteFile(rawPath, combined.Bytes(), 0o644)
	}

	end := time.Now()
	if log != nil {
		status := "OK"
		if err != nil {
			status = "ERR"
		}
		fmt.Fprintf(log, "[%s] DONE (%s) %s\n", end.Format(time.RFC3339), status, strings.Join(args, " "))
	}

	return err
}

// HTTPAnalysisResult bevat de belangrijkste HTTP/TLS observaties.
type HTTPAnalysisResult struct {
	TargetURL      string `json:"target_url"`
	StatusCode     int    `json:"status_code"`
	Server         string `json:"server"`
	PoweredBy      string `json:"powered_by"`
	HasCSP         bool   `json:"has_csp"`
	HasHSTS        bool   `json:"has_hsts"`
	HasXFO         bool   `json:"has_x_frame_options"`
	HasReferrer    bool   `json:"has_referrer_policy"`
	HasPermissions bool   `json:"has_permissions_policy"`
	LatencyMillis  int64  `json:"latency_ms"`
}

// runHTTPAnalysis haalt de site op, kijkt naar security headers / basisinformatie
// en geeft naast de menselijke tekst ook een gestructureerd resultaat terug.
func runHTTPAnalysis(domain string, out *bytes.Buffer, timeout time.Duration) (*HTTPAnalysisResult, error) {
	client := &http.Client{
		Timeout: timeout,
	}

	urls := []string{"https://" + domain, "http://" + domain}
	var resp *http.Response
	var err error
	var usedURL string

	start := time.Now()
	for _, u := range urls {
		usedURL = u
		req, rErr := http.NewRequest(http.MethodGet, u, nil)
		if rErr != nil {
			err = rErr
			continue
		}
		req.Header.Set("User-Agent", "lucaskit-scan/"+version)
		resp, err = client.Do(req)
		if err == nil {
			break
		}
	}

	if err != nil {
		fmt.Fprintf(out, "Kon geen HTTP(S) verbinding maken: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")
	csp := headerExists(resp.Header, "Content-Security-Policy")
	hsts := headerExists(resp.Header, "Strict-Transport-Security")
	xss := headerExists(resp.Header, "X-XSS-Protection")
	xfo := headerExists(resp.Header, "X-Frame-Options")
	referrer := headerExists(resp.Header, "Referrer-Policy")
	permissions := headerExists(resp.Header, "Permissions-Policy")

	fmt.Fprintf(out, "Target URL: %s\n", usedURL)
	fmt.Fprintf(out, "Status Code: %d\n", resp.StatusCode)
	fmt.Fprintf(out, "Server Header: %s\n", emptyDash(server))
	if poweredBy != "" {
		fmt.Fprintf(out, "X-Powered-By: %s\n", poweredBy)
	}
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Security Headers:")
	writeHeaderStatus(out, "Content-Security-Policy", csp)
	writeHeaderStatus(out, "Strict-Transport-Security", hsts)
	writeHeaderStatus(out, "X-XSS-Protection", xss)
	writeHeaderStatus(out, "X-Frame-Options", xfo)
	writeHeaderStatus(out, "Referrer-Policy", referrer)
	writeHeaderStatus(out, "Permissions-Policy", permissions)

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Op basis van bovenstaande headers worden in het rapport aanbevelingen opgenomen.")

	latency := time.Since(start).Milliseconds()

	res := &HTTPAnalysisResult{
		TargetURL:      usedURL,
		StatusCode:     resp.StatusCode,
		Server:         server,
		PoweredBy:      poweredBy,
		HasCSP:         csp,
		HasHSTS:        hsts,
		HasXFO:         xfo,
		HasReferrer:    referrer,
		HasPermissions: permissions,
		LatencyMillis:  latency,
	}

	return res, nil
}

func headerExists(h http.Header, name string) bool {
	return h.Get(name) != ""
}

func writeHeaderStatus(w io.Writer, name string, present bool) {
	status := "MISSING"
	if present {
		status = "OK"
	}
	fmt.Fprintf(w, "  - %s: %s\n", name, status)
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// deriveHTTPFindings maakt enkele basisbevindingen op basis van HTTP headers.
func deriveHTTPFindings(h HTTPAnalysisResult, riskLevel, domain string) []finding {
	var out []finding

	// Missing HTTPS / HSTS
	if !strings.HasPrefix(h.TargetURL, "https://") || !h.HasHSTS {
		severity := "medium"
		if riskLevel == "strict" || !strings.HasPrefix(h.TargetURL, "https://") {
			severity = "high"
		}
		out = append(out, finding{
			ID:       "http_https_hsts",
			Title:    "Geen strikte HTTPS afdwinging (HSTS ontbreekt of HTTP blijft bereikbaar)",
			Severity: severity,
			Description: "De site wordt niet volledig beschermd door HSTS en/of is nog via onversleutelde HTTP bereikbaar. " +
				"Dit vergroot de kans op man-in-the-middle-aanvallen en downgrade-aanvallen.",
			Evidence: fmt.Sprintf("Target URL: %s, HSTS aanwezig: %v", h.TargetURL, h.HasHSTS),
			ReproductionSteps: []string{
				fmt.Sprintf("curl -I %s", h.TargetURL),
			},
			Recommendation: "Zorg dat alle HTTP-verkeer permanent wordt geredirect naar HTTPS en configureer de Strict-Transport-Security header met een voldoende hoge max-age en includeSubDomains.",
		})
	}

	// Missing CSP
	if !h.HasCSP {
		out = append(out, finding{
			ID:       "missing_csp",
			Title:    "Content-Security-Policy ontbreekt",
			Severity: "medium",
			Description: "Er is geen Content-Security-Policy header aangetroffen. Zonder CSP is het lastiger om XSS en content-injectie tegen te gaan.",
			Evidence:  "Header 'Content-Security-Policy' niet aanwezig in HTTP-respons.",
			ReproductionSteps: []string{
				fmt.Sprintf("curl -I %s | grep -i \"content-security-policy\" || echo 'geen CSP header'", h.TargetURL),
			},
			Recommendation: "Definieer een strikte Content-Security-Policy die alleen vertrouwde bronnen toestaat en inline-scripts zoveel mogelijk blokkeert.",
		})
	}

	// Info over server header
	if h.Server != "" {
		out = append(out, finding{
			ID:       "server_header_info",
			Title:    "Server header geeft technologie bloot",
			Severity: "low",
			Description: "De Server header is aanwezig en kan informatie over de gebruikte webserver of CDN prijsgeven. Dit is meestal geen directe kwetsbaarheid, maar kan helpen bij gerichte aanvallen.",
			Evidence:  fmt.Sprintf("Server header: %s", h.Server),
			ReproductionSteps: []string{
				fmt.Sprintf("curl -I %s | grep -i \"server:\"", h.TargetURL),
			},
			Recommendation: "Overweeg om de Server header te minimaliseren of te verwijderen waar mogelijk, of te vervangen door een generieke waarde.",
		})
	}

	// Info finding: performance / latency
	out = append(out, finding{
		ID:       "latency_overview",
		Title:    "Gemeten latency naar hoofddomein",
		Severity: "info",
		Description: "De gemeten HTTP-responsetijd geeft een indicatie van de performance en mogelijke gevoeligheid voor volumetrische aanvallen.",
		Evidence:  fmt.Sprintf("Latency: %d ms, Status: %d, URL: %s", h.LatencyMillis, h.StatusCode, h.TargetURL),
		ReproductionSteps: []string{
			fmt.Sprintf("time curl -o /dev/null -s -w '%%{http_code}\\n' %s", h.TargetURL),
		},
		Recommendation: "Monitor de latency periodiek en overweeg caching/CDN als de responstijd structureel hoog is.",
	})

	return out
}

// writeReport bouwt een uitgebreid PDF rapport (meerdere pagina's).
func writeReport(dir, domain, ultraPrimary, ultraExtra, httpInfo, sitestressInfo, methodology string, findings []finding, includeRaw bool) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("lucaskit_report_%s_%s.pdf", sanitizeFilename(domain), timestamp)
	path := filepath.Join(dir, filename)

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("Lucas Kit – SiteStress / UltraDNS Analyse", false)
	pdf.SetAuthor("Lucas Kit", false)

	addPage := func(title string) {
		pdf.AddPage()
		pdf.SetFont("Helvetica", "B", 24)
		pdf.Cell(0, 10, "LUCAS KIT")
		pdf.Ln(12)
		pdf.SetFont("Helvetica", "", 14)
		pdf.Cell(0, 8, "SITESTRESS / ANALYSIS / (v"+version+")")
		pdf.Ln(10)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.Cell(0, 7, title)
		pdf.Ln(9)
		pdf.SetFont("Helvetica", "", 10)
	}

	// Page 1 – Executive Summary & Scope
	addPage("Executive Summary & Scope")
	pdf.SetFont("Helvetica", "", 10)

	// Algemene gegevens van scan (rechtsboven)
	pdf.SetXY(130, 40)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.Cell(0, 6, "Algemene gegevens van scan")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.Cell(30, 5, "Domein:")
	pdf.SetFont("Helvetica", "", 10)
	pdf.Cell(0, 5, domain)
	pdf.Ln(5)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.Cell(30, 5, "Scan datum:")
	pdf.SetFont("Helvetica", "", 10)
	pdf.Cell(0, 5, time.Now().Format(time.RFC1123))
	pdf.Ln(10)

	// Linkerzijde: Executive Summary
	pdf.SetXY(20, 60)
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 6, "Executive Summary")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 10)
	execText := "In deze scan is gekeken naar DNS-configuratie, mail security, HTTP(S) security headers en de weerbaarheid tegen volumetrische en applicatiegerichte DDoS-aanvallen. " +
		"De beoordeling is gebaseerd op de UltraDNS-output, HTTP-analyse en de SiteStress measure. Deze rapportage is bedoeld als management- en technisch overzicht."
	pdf.MultiCell(0, 5, execText, "", "", false)
	pdf.Ln(3)
	bullets := []string{
		"Is de site op hoofdlijnen veilig bereikbaar en correct geconfigureerd?",
		"Welke misconfiguraties en zwaktes kunnen misbruikt worden?",
		"Hoe gevoelig is de site voor DDoS-aanvallen volgens de huidige metingen?",
		"Welke directe verbeteracties zijn aanbevolen?",
	}
	for _, btxt := range bullets {
		pdf.Cell(5, 5, "•")
		pdf.MultiCell(0, 5, btxt, "", "", false)
	}

	pdf.Ln(4)
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 6, "Scope")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 10)
	scopeLines := []string{
		"In scope: publiek bereikbare HTTP(S)-services op het hoofddomein, DNS-records (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/SRV) en mail-security configuratie (SPF/DMARC/DKIM/MTA-STS/TLS-RPT).",
		"In scope: publiek zichtbare subdomeinen via Certificate Transparency (crt.sh).",
		"Out of scope: interne systemen, VPN's, niet-publieke API's en netwerkcomponenten achter de edge.",
		"Belangrijk: Zonder duidelijke schriftelijke toestemming mag deze methodologie uitsluitend worden toegepast op eigen infrastructuur.",
	}
	for _, line := range scopeLines {
		pdf.Cell(5, 5, "•")
		pdf.MultiCell(0, 5, line, "", "", false)
	}

	// Page 2 – Methodology & Tools
	addPage("Methodology & Tools")
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 6, "Methodology")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 10)
	pdf.MultiCell(0, 5, "Per fase zijn de gebruikte tools en exacte commands vastgelegd zodat de scan volledig reproduceerbaar is. Iedere stap is voorzien van tijdstempels in de CLI-output.", "", "", false)
	pdf.Ln(4)
	for _, line := range strings.Split(methodology, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		pdf.MultiCell(0, 4.5, line, "", "", false)
	}

	pdf.Ln(4)
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 6, "Tools & Environment (voorbeeld)")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 10)
	tools := []string{
		"SiteStress " + version + " (measure-modus; geen destructieve aanval zonder expliciete toestemming).",
		"UltraDNS " + version + " voor DNS-, WHOIS- en mailsecurity-informatie.",
		"lucaskit -d " + domain + " -scan als orchestrator voor alle stappen.",
		"macOS of Kali Linux VM voor het uitvoeren van de tests.",
	}
	for _, t := range tools {
		pdf.Cell(5, 5, "•")
		pdf.MultiCell(0, 5, t, "", "", false)
	}

	// Page 3 – UltraDNS details
	addPage("UltraDNS – DNS, WHOIS & Subdomains")
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 4.5, strings.TrimSpace(ultraPrimary), "", "", false)
	pdf.Ln(3)
	pdf.MultiCell(0, 4.5, strings.TrimSpace(ultraExtra), "", "", false)

	// Page 4 – HTTP security & DDoS interpretatie
	addPage("HTTP(S) Security Headers & DDoS Interpretatie")
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 4.5, strings.TrimSpace(httpInfo), "", "", false)
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.Cell(0, 6, "Interpretatie weerbaarheid tegen DDoS")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 10)
	ddosText := "De HTTP-headeranalyse wordt gecombineerd met de SiteStress measure om een inschatting te maken van de weerbaarheid tegen DDoS-aanvallen. " +
		"Een presence van een CDN/WAF (bijvoorbeeld Cloudflare/Akamai/Fastly) en snelle responstijden duiden op een hogere weerbaarheid. " +
		"Afwezigheid van dergelijke beschermlagen en trage responstijden kunnen wijzen op hogere gevoeligheid."
	pdf.MultiCell(0, 5, ddosText, "", "", false)

	// Page 5 – SiteStress measure & findings overzicht
	addPage("SiteStress Measure & Findings")
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 4.5, strings.TrimSpace(sitestressInfo), "", "", false)
	pdf.Ln(6)

	// Findings tabel
	pdf.SetFont("Helvetica", "B", 11)
	pdf.Cell(0, 6, "Findings / Vulnerabilities")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 10)

	if len(findings) == 0 {
		pdf.MultiCell(0, 5, "Er zijn geen concrete bevindingen geregistreerd. Controleer handmatig of alle beveiligingsmaatregelen op orde zijn.", "", "", false)
	} else {
		for _, f := range findings {
			pdf.SetFont("Helvetica", "B", 10)
			pdf.MultiCell(0, 5, fmt.Sprintf("[%s] %s", strings.ToUpper(f.Severity), f.Title), "", "", false)
			pdf.SetFont("Helvetica", "", 9)
			pdf.MultiCell(0, 4.5, "Beschrijving: "+f.Description, "", "", false)
			pdf.MultiCell(0, 4.5, "Evidence: "+f.Evidence, "", "", false)
			if len(f.ReproductionSteps) > 0 {
				pdf.MultiCell(0, 4.5, "Reproduceer met:", "", "", false)
				for _, step := range f.ReproductionSteps {
					pdf.Cell(4, 4, "•")
					pdf.MultiCell(0, 4.5, step, "", "", false)
				}
			}
			if f.Recommendation != "" {
				pdf.MultiCell(0, 4.5, "Aanbeveling: "+f.Recommendation, "", "", false)
			}
			pdf.Ln(3)
		}
	}

	pdf.Ln(4)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.Cell(0, 6, "Legal")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 9)
	legal := "Gebruik Lucas Kit (UltraDNS / SiteStress / lucaskit) uitsluitend op systemen waar expliciete toestemming voor is gegeven. " +
		"De auteur en Lucas Kit zijn niet aansprakelijk voor misbruik of enige vorm van schade ontstaan door gebruik van deze tooling of dit rapport."
	pdf.MultiCell(0, 4.5, legal, "", "", false)

	// Optionele Appendix met ruwe command-output
	if includeRaw {
		addPage("Appendix – Ruwe output & commands")
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(0, 4.5, "Zie ook commands.log en raw/*.txt in de rapportmap voor volledige uitvoer van alle gebruikte commands.", "", "", false)
	}

	if err := pdf.OutputFileAndClose(path); err != nil {
		return "", err
	}

	return path, nil
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


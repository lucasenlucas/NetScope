package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

const version = "3.4.2"

type scanOptions struct {
	domain    string
	doScan    bool
	outputDir string
}

func main() {
	var o scanOptions

	flag.StringVar(&o.domain, "d", "", "Domein (bijv. example.com)")
	flag.BoolVar(&o.doScan, "scan", false, "Voer een volledige Lucas Kit analyse uit (UltraDNS + SiteStress + HTTP headers)")
	flag.StringVar(&o.outputDir, "o", "", "Map om het rapport in op te slaan (default: huidige map)")

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

	if o.domain == "" || !o.doScan {
		printHelp()
		os.Exit(2)
	}

	domain := normalizeDomain(o.domain)
	if domain == "" {
		fmt.Println("❌ Ongeldig domein.")
		os.Exit(2)
	}

	if o.outputDir == "" {
		o.outputDir = "."
	}
	if err := os.MkdirAll(o.outputDir, 0o755); err != nil {
		fmt.Printf("❌ Kon output map niet maken: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[%s] 🚀 Start Lucas Kit scan voor %s\n", now(), domain)

	steps := []string{
		"UltraDNS basisinformatie ophalen",
		"UltraDNS subdomeinen en WHOIS ophalen",
		"HTTP(S) headers & security analyse",
		"SiteStress measure uitvoeren (zonder aanval)",
		"Rapport genereren",
	}

	progress := newProgressBar(len(steps))

	// Buffers voor het rapport
	var ultraPrimary bytes.Buffer
	var ultraExtra bytes.Buffer
	var httpInfo bytes.Buffer
	var sitestressMeasure bytes.Buffer
	var methodology bytes.Buffer

	methodology.WriteString("### Methodology & Commands\n\n")
	methodology.WriteString("Alle stappen zijn reproduceerbaar met de volgende handmatige commands:\n\n")

	// STEP 1: UltraDNS basisinfo (-inf -n)
	progress.Step(1, steps[0])
	cmd1 := []string{"ultradns", "-d", domain, "-inf", "-n"}
	appendCommand(&methodology, cmd1)
	if err := runCommandStreaming(cmd1, &ultraPrimary); err != nil {
		fmt.Printf("\n[%s] ⚠️ UltraDNS basisinformatie gaf een fout: %v\n", now(), err)
	}

	// STEP 2: UltraDNS subdomeinen + whois
	progress.Step(2, steps[1])
	cmd2 := []string{"ultradns", "-d", domain, "-subs", "-whois"}
	appendCommand(&methodology, cmd2)
	if err := runCommandStreaming(cmd2, &ultraExtra); err != nil {
		fmt.Printf("\n[%s] ⚠️ UltraDNS extra informatie gaf een fout: %v\n", now(), err)
	}

	// STEP 3: HTTP header analyse
	progress.Step(3, steps[2])
	if err := runHTTPAnalysis(domain, &httpInfo); err != nil {
		fmt.Printf("\n[%s] ⚠️ HTTP analyse gaf een fout: %v\n", now(), err)
	}
	methodology.WriteString("- HTTP analyse: intern uitgevoerd via lucaskit (GET https://")
	methodology.WriteString(domain)
	methodology.WriteString(" met fallback naar http://")
	methodology.WriteString(domain)
	methodology.WriteString(")\n")

	// STEP 4: SiteStress measure
	progress.Step(4, steps[3])
	cmd4 := []string{"sitestress", "-measure", "-d", domain}
	appendCommand(&methodology, cmd4)
	if err := runCommandStreaming(cmd4, &sitestressMeasure); err != nil {
		fmt.Printf("\n[%s] ⚠️ SiteStress measure gaf een fout: %v\n", now(), err)
	}

	// STEP 5: Rapport
	progress.Step(5, steps[4])
	reportPath, err := writeReport(o.outputDir, domain, ultraPrimary.String(), ultraExtra.String(), httpInfo.String(), sitestressMeasure.String(), methodology.String())
	if err != nil {
		fmt.Printf("\n[%s] ❌ Kon rapport niet opslaan: %v\n", now(), err)
		os.Exit(1)
	}

	progress.Finish()
	fmt.Printf("\n[%s] ✅ Scan voltooid. Rapport: %s\n", now(), reportPath)
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
}

func newProgressBar(total int) *progressBar {
	return &progressBar{total: total}
}

func (p *progressBar) Step(current int, label string) {
	if p.total <= 0 {
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
	fmt.Printf("\n")
}

// runCommandStreaming voert een extern command uit, toont live output en schrijft naar buffer.
func runCommandStreaming(args []string, buf *bytes.Buffer) error {
	if len(args) == 0 {
		return fmt.Errorf("geen command")
	}
	fmt.Printf("\n[%s] ▶ CMD: %s\n", now(), strings.Join(args, " "))

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

	mw := io.MultiWriter(os.Stdout, buf)

	go io.Copy(mw, stdout)
	go io.Copy(mw, stderr)

	if err := cmd.Wait(); err != nil {
		return err
	}
	return nil
}

// runHTTPAnalysis haalt de site op en kijkt naar security headers / basisinformatie.
func runHTTPAnalysis(domain string, out *bytes.Buffer) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	urls := []string{"https://" + domain, "http://" + domain}
	var resp *http.Response
	var err error
	var usedURL string

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
		return err
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

	return nil
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

// writeReport bouwt een uitgebreid PDF rapport (meerdere pagina's).
func writeReport(dir, domain, ultraPrimary, ultraExtra, httpInfo, sitestressInfo, methodology string) (string, error) {
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

	// Page 5 – SiteStress measure & findings
	addPage("SiteStress Measure & Findings")
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 4.5, strings.TrimSpace(sitestressInfo), "", "", false)
	pdf.Ln(4)

	pdf.SetFont("Helvetica", "B", 11)
	pdf.Cell(0, 6, "Risk Rating / Overzichtstabel (concept)")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 10)
	tableLines := []string{
		"Issue            | Severity | Status",
		"-----------------|----------|-------",
		"XSS / Injectie   | High     | Open (afhankelijk van headers & app-code)",
		"Headers          | Medium   | Open (zie ontbrekende security headers)",
		"DDoS / Load      | Variabel | Zie SiteStress measure advies",
	}
	for _, l := range tableLines {
		pdf.MultiCell(0, 4.5, l, "", "", false)
	}

	pdf.Ln(6)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.Cell(0, 6, "Findings / Vulnerabilities (template)")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 10)
	findLines := []string{
		"Per gevonden issue kan onderstaande structuur gebruikt worden:",
		"• Titel",
		"• Risico (Low / Medium / High / Critical)",
		"• Beschrijving",
		"• Impact",
		"• Bewijs (screenshots/logs/CLI-output)",
		"• Oplossing / aanbeveling",
		"",
		"Voorbeeld – Finding #1: Missing Security Headers",
		"Severity: Medium / High (afhankelijk van applicatie).",
		"Description: De website gebruikt geen of beperkte security headers zoals Content-Security-Policy of Strict-Transport-Security.",
		"Impact: Verhoogde kans op XSS, clickjacking en informatielekken.",
		"Evidence: Zie HTTP(S) headers sectie in dit rapport.",
		"Recommendation: Implementeer minimaal CSP, HSTS, X-Frame-Options, Referrer-Policy en Permissions-Policy.",
	}
	for _, l := range findLines {
		pdf.MultiCell(0, 4.5, l, "", "", false)
	}

	pdf.Ln(4)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.Cell(0, 6, "Legal")
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 9)
	legal := "Gebruik Lucas Kit (UltraDNS / SiteStress / lucaskit) uitsluitend op systemen waar expliciete toestemming voor is gegeven. " +
		"De auteur en Lucas Kit zijn niet aansprakelijk voor misbruik of enige vorm van schade ontstaan door gebruik van deze tooling of dit rapport."
	pdf.MultiCell(0, 4.5, legal, "", "", false)

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
	fmt.Println("  lucaskit -d <domein> -scan [-o <output_dir>]")
	fmt.Println()
	fmt.Println("Beschrijving:")
	fmt.Println("  Voert een volledige analyse uit met UltraDNS, SiteStress (measure) en een HTTP security header check,")
	fmt.Println("  en genereert een professioneel PDF-rapport (meerdere pagina's) met alle outputs, verbeterpunten en gebruikte commands.")
	fmt.Println()
	fmt.Println("Belangrijkste opties:")
	fmt.Println("  -d <domein>    : Doel-domein (bijv. example.com)")
	fmt.Println("  -scan          : Start de Lucas Kit scan workflow")
	fmt.Println("  -o <map>       : Map waarin het rapport wordt opgeslagen (default: huidige map)")
	fmt.Println("  --help / -h    : Toon deze helptekst")
	fmt.Println("  --version      : Toon lucaskit versie")
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


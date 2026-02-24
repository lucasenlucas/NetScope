package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const version = "4.3.0"

type options struct {
	domain  string
	help    bool
	version bool

	// DNS & Mail Flags
	inf      bool
	n        bool
	whois    bool
	subs     bool
	a        bool
	aaaa     bool
	cname    bool
	mx       bool
	ns       bool
	txt      bool
	soa      bool
	caa      bool
	srv      bool
	records  string
	resolve  string
	dnssec   bool
	resolver string
	timeout  time.Duration

	// Web Security & Analysis Flags
	httpCheck    bool
	tlsCheck     bool
	headersCheck bool
	cacheCheck   bool
	fingerCheck  bool
	portsCheck   bool
	pathsCheck   bool
	corsCheck    bool
	cookieCheck  bool
	techCheck    bool
	crawlerCheck bool
	methodCheck  bool

	// Vulnerability & SecLists Flags
	dirCheck    bool
	paramsCheck bool
	cmsCheck    bool

	// Stress Test Flags
	measure       bool
	probes        int
	attackMinutes int
	concurrency   int
	level         int
	noKeepAlive   bool

	// General Options
	jsonOut   bool
	outputDir string
	check     bool
	update    bool
}

func main() {
	var o options

	// General
	flag.StringVar(&o.domain, "d", "", "Domein(en) om te analyseren of testen (bijv. example.com)")
	flag.BoolVar(&o.jsonOut, "json", false, "Output resultaten als JSON")
	flag.StringVar(&o.outputDir, "o", "", "Map om logging/resultaten in op te slaan (voor stresstests)")
	flag.BoolVar(&o.help, "help", false, "Toon deze help pagina")
	flag.BoolVar(&o.help, "h", false, "Korte help vlag")
	flag.BoolVar(&o.version, "version", false, "Toon NetScope versie")
	flag.BoolVar(&o.check, "check", false, "Controleer op updates")
	flag.BoolVar(&o.update, "update", false, "Update naar de nieuwste versie")

	// DNS & Mail
	flag.BoolVar(&o.inf, "inf", false, "DNS + Mail checks (combineer met -n of -whois)")
	flag.BoolVar(&o.n, "n", false, "Alle DNS records info (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/SRV) + Mail")
	flag.BoolVar(&o.whois, "whois", false, "WHOIS info (registratie/nameservers)")
	flag.BoolVar(&o.subs, "subs", false, "Subdomeinen verzamelen via Certificate Transparency")
	flag.BoolVar(&o.a, "a", false, "Alleen A records (IPv4)")
	flag.BoolVar(&o.aaaa, "aaaa", false, "Alleen AAAA records (IPv6)")
	flag.BoolVar(&o.cname, "cname", false, "Alleen CNAME records")
	flag.BoolVar(&o.mx, "mx", false, "Alleen MX records")
	flag.BoolVar(&o.ns, "ns", false, "Alleen NS records")
	flag.BoolVar(&o.txt, "txt", false, "Alleen TXT records")
	flag.BoolVar(&o.soa, "soa", false, "Alleen SOA records")
	flag.BoolVar(&o.caa, "caa", false, "Alleen CAA records")
	flag.BoolVar(&o.srv, "srv", false, "Alleen SRV records")
	flag.StringVar(&o.records, "records", "", "Specifieke DNS records (bijv: A,AAAA,MX)")
	flag.StringVar(&o.resolve, "resolve", "", "Alias voor -records")
	flag.BoolVar(&o.dnssec, "dnssec", false, "Controleer op DNSSEC (DNSKEY/DS)")
	flag.StringVar(&o.resolver, "r", "", "Specifieke DNS resolver (bijv. 8.8.8.8:53)")
	flag.DurationVar(&o.timeout, "timeout", 5*time.Second, "Timeout per DNS query")

	// Web Security & Analysis
	flag.BoolVar(&o.httpCheck, "http", false, "Analyseer HTTP redirects en final URL")
	flag.BoolVar(&o.tlsCheck, "tls", false, "Analyseer TLS certificaten")
	flag.BoolVar(&o.headersCheck, "headers", false, "Controleer security headers (HSTS/CSP)")
	flag.BoolVar(&o.cacheCheck, "cache", false, "Controleer caching configuratie")
	flag.BoolVar(&o.fingerCheck, "fingerprint", false, "Basis server fingerprinting")
	flag.BoolVar(&o.portsCheck, "ports", false, "Scan op veelvoorkomende open poorten")
	flag.BoolVar(&o.pathsCheck, "paths", false, "Controleer bekende paden (robots.txt, .env)")
	flag.BoolVar(&o.corsCheck, "cors", false, "Test op excessief permissieve CORS")
	flag.BoolVar(&o.cookieCheck, "cookies", false, "Analyseer sessie cookies (Secure/HttpOnly)")
	flag.BoolVar(&o.techCheck, "tech", false, "CMS/Framework detectie (WordPress, React, etc)")
	flag.BoolVar(&o.crawlerCheck, "crawlers", false, "Controleer robots.txt op AI/LLM crawler protectie")
	flag.BoolVar(&o.methodCheck, "methods", false, "Controleer toegestane HTTP methoden via OPTIONS")

	// Vulnerability & SecLists
	flag.BoolVar(&o.dirCheck, "dir", false, "Uitgebreide Directory & File Busting (SecLists)")
	flag.BoolVar(&o.paramsCheck, "params", false, "Verborgen Parameter Discovery fuzzing")
	flag.BoolVar(&o.cmsCheck, "cms", false, "CMS Discovery Scanner (WordPress, Joomla, etc)")

	// Stress Test
	flag.BoolVar(&o.measure, "measure", false, "Meet de bereikbaarheid/latency van de site")
	flag.IntVar(&o.probes, "probes", 1, "Aantal probes voor de measurement (default: 1)")
	flag.IntVar(&o.attackMinutes, "t", 0, "Aantal minuten voor L7 Stress Test")
	flag.IntVar(&o.concurrency, "c", 0, "Aantal attack workers (overschrijft level uiteraard)")
	flag.IntVar(&o.level, "level", 0, "Attack Power Level (1-10, 10=EXTREME)")
	flag.BoolVar(&o.noKeepAlive, "no-keepalive", false, "Schakel Keep-Alive uit bij stress test (verzadigt sockets sneller)")

	flag.Usage = func() {
		printBanner(version)
		fmt.Fprintf(os.Stderr, "Gebruik: netscope -d <domein> [flags]\n\n")

		printBoxedSection("🎯 ALGEMEEN & DOELWIT", []flagHelp{
			{"-d, --domain", "Het domein dat je wilt analyseren of testen"},
			{"-json", "Formatteer output strak als JSON (voor integraties)"},
			{"-o, --outputDir", "Exporteer rapportages en stress-logs naar specifieke map"},
			{"-check", "Controleer online of er een nieuwe versie is"},
			{"-update", "Update NetScope direct naar de nieuwste netscope binary"},
			{"-h, --help", "Toon dit interactieve help-scherm"},
			{"-version", "Toon huidige NetScope core versie"},
		})

		printBoxedSection("🌐 DNS & MAIL SECURITY", []flagHelp{
			{"-inf", "Meest uitgebreide DNS + Mail security weergave"},
			{"-n", "Haal alle standaard records op + MX/Mailchecks"},
			{"-whois", "Vraag WHOIS registratiedata en Root Nameservers op"},
			{"-subs", "Reconstrueer subdomeinen middels Certificate Transparency"},
			{"-dnssec", "Valideer de aanwezigheid van DNSSEC/DS/DNSKEY"},
			{"-r, --resolver", "Gebruik custom upstream resolver (default: system/8.8.8.8)"},
			{"-records", "Specifieke queries (comma gescheiden: A,MX,TXT)"},
			{"-(a,aaaa,mx...)", "Individuele boolean flags voor specifieke DNS records"},
		})

		printBoxedSection("🛡️  WEB SECURITY & ANALYSE", []flagHelp{
			{"-http", "Valideer redirect ketens en de uiteindelijke HTTP URL"},
			{"-tls", "Uitgebreide controle van het SSL/TLS Certificaat"},
			{"-headers", "Controle op verplichte veiligheidsheaders (CSP/HSTS)"},
			{"-cookies", "Zoek naar onbeveiligde session cookies die via MITM lekken"},
			{"-cors", "Controleer of externe domeinen onrechtmatig API calls kunnen maken"},
			{"-methods", "Zoek naar risicovolle HTTP Methods (PUT/DELETE/TRACE)"},
			{"-ports", "Basis Poortscanner (21, 22, 3306, 3389 etc)"},
			{"-paths", "Check configuratie-lek paden (/.env, /.git/config, /robots.txt)"},
			{"-tech", "Fingerprint Frameworks middels source crawling (WP, React, Nginx)"},
			{"-crawlers", "Controleer of de applicatie data-scraping door AI (LLM Bot) blokkeert"},
		})

		printBoxedSection("🔍 DISCOVERY & ANALYSE", []flagHelp{
			{"-dir", "Uitgebreide Directory & File Busting (downloadt SecLists)"},
			{"-params", "Verborgen Parameter Discovery (Fuzzing)"},
			{"-cms", "Agressieve CMS & Plugin discovery (WP/Joomla)"},
		})

		printBoxedSection("⚡ CAPACITEITS & L7 STRESS TEST", []flagHelp{
			{"-measure", "Meet latency en web-server implementatie met 'N' probes"},
			{"-probes", "Hoeveel iteraties de measure tool vergaart (default: 1)"},
			{"-t", "Tijdsduur (in minuten) dat aanval is gepland (VERPLICHT VOOR ATTACK)"},
			{"-level", "Abstractieniveau L7 Stress (1=Zacht | 10=Kritieke Massa)"},
			{"-c", "Absolute hoeveelheid netwerk-vullende workers/RPS"},
			{"-no-keepalive", "Schakel persistent verbinding uit; maximaal socket verbruik"},
		})

		fmt.Fprintf(os.Stderr, "\nVoorbeelden:\n")
		fmt.Fprintf(os.Stderr, "  NetScope -check\n")
		fmt.Fprintf(os.Stderr, "  NetScope -d lucasmangroelal.nl -inf -n\n")
		fmt.Fprintf(os.Stderr, "  NetScope -d lucasmangroelal.nl -tls -headers -ports -tech\n")
		fmt.Fprintf(os.Stderr, "  NetScope -d lucasmangroelal.nl -t 15 -level 8 -no-keepalive\n")
	}

	flag.Parse()

	if o.version {
		printBanner(version)
		os.Exit(0)
	}

	if o.help {
		flag.Usage()
		os.Exit(0)
	}

	if o.update {
		printBanner(version)
		runAutoUpdate()
		os.Exit(0)
	}

	if o.check {
		printBanner(version)
		runCheckUpdate()
		os.Exit(0)
	}

	if o.domain == "" {
		runDiscoveryWizard(o)
		return
	}

	if !o.jsonOut {
		printBanner(version)
	}

	if o.attackMinutes > 0 {
		applyLevelSettings(&o)
		runAttack([]string{o.domain}, o)
		return
	}

	runUnifiedAnalysis(o)
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimSuffix(d, "/")
	return strings.TrimSuffix(d, ".")
}

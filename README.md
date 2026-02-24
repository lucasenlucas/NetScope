# NetScope (v4.3.0)
Formerly known as Lucas Kit, UltraDNS, and SiteStress.

NetScope is an all-in-one DNS and HTTP discovery engine, combining advanced network enumeration capabilities with Layer 7 volumetric stress testing functionalities.

**Author**: Lucas Mangroelal | [lucasmangroelal.nl](https://lucasmangroelal.nl)

## Features
- **DNS Enumeration (`-inf`, `-whois`, `-subs`)**: Perform comprehensive DNS mapping, Certificate Transparency log parsing, and Mail Security (SPF, DKIM, DMARC) validation.
- **Web Analytics (`-http`, `-tls`, `-headers`, `-ports`, `-paths`)**: Scan web infrastructures for missing security headers, open administrative ports, sensitive configuration paths, permissive CORS, insecure cookies, and more.
- **Discovery & Analyser (`-dir`, `-params`, `-cms`)**: Discover hidden directories, files, and parameters. Perform deep CMS & Plugin analysis for WordPress, Joomla, and more.
- **Powerful L7 Stress Testing (`-t`, `-c`, `-level`)**: Multi-threaded HTTP/HTTPS volumetric stress tester with randomized Referrers, User-Agents, and Cache-Bypassing logic to assess CDN resilience.
- **Bot Detection (`-crawlers`)**: Verify if robots.txt properly mitigates AI aggregator/spider indexing.

## Installation

### Quick Install (macOS & Linux)
You can easily install NetScope with a single command:
```bash
curl -fsSL https://raw.githubusercontent.com/lucasenlucas/NetScope/main/scripts/install.sh | sh
```

### Quick Install (Windows)
Open PowerShell as Administrator and run:
```powershell
irm https://raw.githubusercontent.com/lucasenlucas/NetScope/main/scripts/install.ps1 | iex
```

### Compilation (From Source)
Requires Go `1.22` or higher.
```bash
git clone https://github.com/lucasenlucas/NetScope.git
cd NetScope
make build
./netscope --help
```

_This tool is part of the Lucas Kit platform._

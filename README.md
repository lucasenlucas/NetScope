# Lucas Kit (`lucaskit`)

> The ultimate domain toolkit containing **UltraDNS** and **SiteStress**. Made by Lucas Mangroelal | lucasmangroelal.nl

**Lucas Kit** is een collectie van krachtige tools voor DNS/Domain information gathering en security testing. Het bevat:

1. **UltraDNS** (voorheen LucasDNS): Info gathering (DNS, WHOIS, Mail Security, Subdomains).
2. **SiteStress** (voorheen Lucaskill): Advanced HTTP stress test / load test tool.

## Install

### Kali Linux / macOS / Linux (aanbevolen)

**Automatische installatie (detecteert architecture):**

```bash
curl -fsSL https://raw.githubusercontent.com/lucasenlucas/Lucas_Kit/main/scripts/install.sh | sh
```

Dit installeert `ultradns` en `sitestress` naar `/usr/local/bin` (of `~/.local/bin`).

### Windows

**PowerShell:**

```powershell
.\scripts\install.ps1 -Repo "lucasenlucas/Lucas_Kit"
```

## Tools

### 1. UltraDNS (`ultradns`)

Info gathering tool.

```bash
ultradns -d <domein> [flags]
```

**Features:**
- DNS Records (A, AAAA, MX, NS, TXT, SOA, CAA, SRV)
- Mail Security (SPF, DMARC, DKIM, MTA-STS)
- WHOIS informatie
- Certificate Transparency (Subdomeinen)

**Voorbeelden:**
```bash
ultradns -d example.com -inf -n
ultradns -d example.com -subs
```

### 2. SiteStress (`sitestress`)

HTTP stress/load test tool.

```bash
sitestress -d <domein> -t <minuten> -c <concurrency> [flags]
```

**Features:**
- High performance HTTP flooding met custom concurrency (`-c`).
- **Random User-Agents**: Omzeilt simpele blocks door zich voor te doen als Chrome, Firefox, Safari, etc.
- **Connection Modes**: standaard Keep-Alive of gebruik `-no-keepalive` voor connection flooding.
- "Keep-Down" logic: monitort site en valt automatisch weer aan als hij online komt.
- Real-time dashboard.

**Voorbeelden:**
```bash
# Standaard (1000 workers)
sitestress -d example.com -t 10

# Heavy Load (5000 workers)
sitestress -d example.com -t 10 -c 5000

# Connection Flood (geen keep-alive)
sitestress -d example.com -t 5 -no-keepalive
```

> **⚠️ DISCLAIMER:** Gebruik deze tools alleen op systemen waar je expliciete toestemming voor hebt.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Additional Notice on Naming, Forks, and Liability

Use of the names "Lucas Mangroelal", "Lucas DNS", "Lucas Kit", or any related project names associated with the original version of this Software does not imply endorsement by the original author.
Any redistributed, modified, or forked versions must make it clear that they are unofficial versions if they are not directly maintained by Lucas Mangroelal.
Lucas Mangroelal is not responsible or liable for any misuse, damages, or consequences resulting from third-party copies, forks, or modified versions of this Software.

For more information, permissions regarding naming, or official inquiries, contact:
kit@lucasmangroelal.nl

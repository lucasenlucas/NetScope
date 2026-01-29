# Lucas DNS (`lucasdns`)

> Cross-platform DNS en domain informatie tool voor **Kali Linux**, **macOS** en **Windows** terminals. Query DNS records (A/AAAA/MX/NS/TXT/SOA/CAA/SRV), check mail security (SPF/DMARC/DKIM), enumerate subdomains via certificate transparency, en haal WHOIS informatie op - alles in één tool.

Cross-platform DNS/Domain info tool voor **Kali Linux**, **macOS** en **Windows** terminals.

## Install

### Kali Linux (aanbevolen)

**Automatische installatie (detecteert automatisch architecture - amd64/arm64):**

```bash
curl -fsSL https://raw.githubusercontent.com/lucasenlucas/Lucas_DNS/main/scripts/install.sh | sh
```

De installer:
- ✅ Detecteert automatisch je architecture (amd64 of arm64)
- ✅ Downloadt de juiste binary
- ✅ Installeert naar `/usr/local/bin` (vereist sudo)
- ✅ Installeert zowel `lucasdns` als `lucaskill` (vanaf v2.1.4)
- ✅ Test of alles werkt

**Na installatie:**
```bash
lucasdns --help
```

### macOS / Andere Linux distributies

**Automatische installatie:**

```bash
curl -fsSL https://raw.githubusercontent.com/lucasenlucas/Lucas_DNS/main/scripts/install.sh | sh
```

**⚠️ Als je geen sudo hebt:** De installer gebruikt dan `~/.local/bin`. Voeg dit toe aan je PATH:

**Voor zsh (macOS standaard):**
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

**Voor bash (Linux):**
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Via Go (als je Go geïnstalleerd hebt)

```bash
go install github.com/lucasenlucas/Lucas_DNS@latest
lucasdns --help
```

### Windows

**PowerShell:**
```powershell
.\scripts\install.ps1 -Repo "lucasenlucas/Lucas_DNS"
```

Of download handmatig de `.zip` voor Windows vanaf de [releases pagina](https://github.com/lucasenlucas/Lucas_DNS/releases).

## Gebruik

```bash
lucasdns -d <domein> <flag(s)>
```

Voorbeelden:

```bash
lucasdns -d lucasmangroelal.nl -subs
lucasdns -d lucasmangroelal.nl -inf -n
lucasdns -d lucasmangroelal.nl -whois
```

## Flags (kort)

- `-inf`: info mode (als je verder niks specificeert: DNS + mail checks + WHOIS)
- `-n`: alle DNS records + mail checks (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA/SRV)
- `-whois`: WHOIS (registratie/expiratie/nameservers waar mogelijk)
- `-subs`: subdomeinen (certificate transparency via `crt.sh`)

Record-only:

- `-a`, `-aaaa`, `-cname`, `-mx`, `-ns`, `-txt`, `-soa`, `-caa`, `-srv`

Extra:


## Lucaskill (Advanced Attack Tool)

De aanvalsfunctionaliteit is verhuisd naar een eigen krachtige tool: **Lucaskill**.

### Gebruik Lucaskill

```bash
lucaskill -d <domein> -t <minuten> [flags]
```

**Flags:**
- `-d`: Target domein(en) (comma-separated)
- `-t`: Tijd in minuten om de aanval vol te houden
- `-o`: Map om rapporten en logs in op te slaan (optioneel)

**Voorbeelden:**

```bash
lucaskill -d target.com -t 10
lucaskill -d target.com -t 60 -o ./logs
```

> **⚠️ DISCLAIMER:** Gebruik deze tool alleen op systemen die van jou zijn of waarvoor je expliciete toestemming hebt.



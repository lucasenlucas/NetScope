# Lucas Kit - Analysis Report

**Domain:** `cyberbrein.nl`
**Date:** 22-02-2026 11:36:03
**Tool Version:** v3.4.5

---

## Executive Summary
In deze scan analyseert Lucas Kit het aangegeven doelwit op mogelijke blootstellingen en configuratiefouten.

## Findings & Aanbevelingen
### Finding #1: TLS Certificaat verloopt binnenkort
- **Severity:** `MEDIUM`
- **Description:** Het certificaat is geldig voor minder dan 14 dagen.
- **Evidence:** Dagen resterend: 5
- **Recommendation:** Vernieuw het TLS certificaat zo snel mogelijk.

### Finding #2: CSP ontbreekt
- **Severity:** `MEDIUM`
- **Description:** Content-Security-Policy header is niet ingesteld.
- **Evidence:** CSP: MISSING
- **Recommendation:** Stel een CSP in om XSS-aanvallen te mitigeren.

### Finding #3: Gevaarlijke poorten blootgesteld
- **Severity:** `HIGH`
- **Description:** Er zijn direct toegankelijke beheer- of databasepoorten ontdekt via het publieke IP adres.
- **Evidence:** Open ports: 22
- **Recommendation:** Sluit deze poorten af via een firewall of beperk toegang uitsluitend tot vertrouwde (VPN) IPs.

### Finding #4: Technologie & Frameworks Gedetecteerd
- **Severity:** `INFO`
- **Description:** Er zijn specifieke CMS systemen of web-technologieen herkend via HTML body of Headers.
- **Evidence:** Detecies: Nginx
- **Recommendation:** Zorg ervoor dat alle gedetecteerde componenten up-to-date zijn ivm CVE risicos.

### Finding #5: Interessante Fuzzing Directories Gevonden
- **Severity:** `HIGH`
- **Description:** Via directory bruteforcing is directe toegang tot administratieve backends of database gerelateerde paden vastgesteld.
- **Evidence:** Positieve Fuzzing paden: /wp-admin (HTTP 200), /admin (HTTP 200), /dashboard (HTTP 200), /login (HTTP 200)
- **Recommendation:** Sluit deze paden direct af, minimaliseer error codes of verplaats authenticatie interfaces achter gesloten firewalls.

### Finding #6: Geen AI Web-Crawler Beveiliging Gespot
- **Severity:** `INFO`
- **Description:** De site verbiedt LLM aggregators (zoals GPTBot, ClaudeBot, Perplexity) niet via robots.txt, waardoor interne open data gebruikt kan worden voor AI model training.
- **Evidence:** Robots.txt mist specifieke Disallow regels voor bekende LLM user-agents.
- **Recommendation:** Indien data privacy en copyright extractie een zorg is, voeg LLM spiders toe aan robots.txt Disallow blokkades.

## Appendix

Genereert door Lucas Kit. Resultaten zijn indicaties voor management en tech-lead doeleinden.


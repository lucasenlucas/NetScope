package main

import (
"context"
"fmt"
"net"
"sort"
"strings"

"github.com/miekg/dns"
)

// Here we define the DNS functions pulled directly from UltraDNS

func runDNSAnalysis(ctx context.Context, o options) {
    domain := normalizeDomain(o.domain)
	resolver := pickResolver(o.resolver)

    // Basic logic mapping from UltraDNS
    if !o.jsonOut {
		fmt.Printf("Starting DNS and Mail Analysis for: %s | Resolver: %s\n\n", domain, resolver)
	}

    // Add rest of the logic...
}

func pickResolver(flagVal string) string {
	if flagVal != "" {
		if strings.Contains(flagVal, ":") {
			return flagVal
		}
		return flagVal + ":53"
	}
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		return net.JoinHostPort(cfg.Servers[0], cfg.Port)
	}
	return "8.8.8.8:53"
}

// Reused queryType from UltraDNS
func queryType(ctx context.Context, client *dns.Client, resolver, name string, qtype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	rctx, cancel := context.WithTimeout(ctx, client.Timeout)
	defer cancel()

	in, _, err := client.ExchangeContext(rctx, m, resolver)
	if err != nil {
		return nil, err
	}
	if in.Rcode != dns.RcodeSuccess && in.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("dns rcode %s", dns.RcodeToString[in.Rcode])
	}
	var out []dns.RR
	out = append(out, in.Answer...)
	out = append(out, in.Extra...)
	return out, nil
}

func extractIPs(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		}
	}
	return out
}

func extractRRStrings(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if rr.Header() != nil && rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		out = append(out, rr.String())
	}
	return out
}

func findTXTContains(rrs []dns.RR, needle string) string {
	needle = strings.ToLower(needle)
	for _, rr := range rrs {
		t, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		joined := strings.Join(t.Txt, "")
		if strings.Contains(strings.ToLower(joined), needle) {
			return joined
		}
	}
	return ""
}

func extractMXHosts(rrs []dns.RR) []string {
	type mxh struct {
		host string
		pref uint16
	}
	var all []mxh
	for _, rr := range rrs {
		m, ok := rr.(*dns.MX)
		if !ok {
			continue
		}
		h := strings.TrimSuffix(m.Mx, ".")
		all = append(all, mxh{host: h, pref: m.Preference})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].pref < all[j].pref })
	out := make([]string, 0, len(all))
	for _, x := range all {
		out = append(out, x.host)
	}
	return out
}

func printRRs(rrs []dns.RR, err error) {
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	if len(rrs) == 0 {
		fmt.Println("(geen records)")
		return
	}
	for _, rr := range rrs {
		if rr.Header() != nil && rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		fmt.Println(rr.String())
	}
}

func printHeader(title string) {
	fmt.Printf("== %s ==\n", title)
}

func runCommonSRV(ctx context.Context, client *dns.Client, resolver, domain string) error {
	labels := []string{
		"_sip._tcp", "_sip._udp", "_sips._tcp",
		"_submission._tcp", "_smtps._tcp",
		"_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
		"_xmpp-client._tcp", "_xmpp-server._tcp",
		"_autodiscover._tcp",
		"_caldav._tcp", "_carddav._tcp",
		"_ldap._tcp",
		"_kerberos._udp", "_kerberos._tcp",
		"_ntp._udp",
	}

	printedAny := false
	for _, l := range labels {
		qname := l + "." + domain
		rrs, err := queryType(ctx, client, resolver, qname, dns.TypeSRV)
		if err != nil || len(rrs) == 0 {
			continue
		}
		hasSRV := false
		for _, rr := range rrs {
			if _, ok := rr.(*dns.SRV); ok {
				hasSRV = true
				break
			}
		}
		if !hasSRV {
			continue
		}

		if !printedAny {
			printedAny = true
		}
		fmt.Printf("  %s\n", qname)
		for _, rr := range rrs {
			if rr.Header() != nil && rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			fmt.Printf("    %s\n", rr.String())
		}
	}

	if !printedAny {
		fmt.Println("(geen SRV records gevonden voor bekende services)")
	}
	return nil
}

func mailChecks(ctx context.Context, client *dns.Client, resolver, domain string) error {
	txt, err := queryType(ctx, client, resolver, domain, dns.TypeTXT)
	if err != nil {
		fmt.Printf("SPF: error: %v\n", err)
	} else {
		spf := findTXTContains(txt, "v=spf1")
		if spf == "" {
			fmt.Println("SPF: niet gevonden")
		} else {
			fmt.Printf("SPF: %s\n", spf)
		}
	}

	dmarcName := "_dmarc." + domain
	dmarc, err := queryType(ctx, client, resolver, dmarcName, dns.TypeTXT)
	if err != nil {
		fmt.Printf("DMARC: error: %v\n", err)
	} else {
		v := findTXTContains(dmarc, "v=DMARC1")
		if v == "" {
			fmt.Println("DMARC: niet gevonden")
		} else {
			fmt.Printf("DMARC: %s\n", v)
		}
	}

	dkimSelectors := []string{"default", "selector1", "selector2", "s1", "s2", "k1", "google"}
	foundDKIM := false
	for _, sel := range dkimSelectors {
		name := sel + "._domainkey." + domain
		rrs, err := queryType(ctx, client, resolver, name, dns.TypeTXT)
		if err != nil {
			continue
		}
		v := findTXTContains(rrs, "v=DKIM1")
		if v != "" {
			if !foundDKIM {
				fmt.Println("DKIM:")
				foundDKIM = true
			}
			fmt.Printf("  - %s: %s\n", sel, v)
		}
	}
	if !foundDKIM {
		fmt.Println("DKIM: niet gevonden (common selectors)")
	}

	mx, err := queryType(ctx, client, resolver, domain, dns.TypeMX)
	if err != nil {
		fmt.Printf("MX: error: %v\n", err)
	} else {
		mxHosts := extractMXHosts(mx)
		if len(mxHosts) == 0 {
			fmt.Println("MX: niet gevonden")
		} else {
			fmt.Printf("MX: %d record(s)\n", len(mxHosts))
			for _, h := range mxHosts {
				fmt.Printf("  - %s\n", h)
				a, _ := queryType(ctx, client, resolver, h, dns.TypeA)
				aaaa, _ := queryType(ctx, client, resolver, h, dns.TypeAAAA)
				if len(a) == 0 && len(aaaa) == 0 {
					fmt.Printf("    resolve: geen A/AAAA\n")
				} else {
					ips := append(extractIPs(a), extractIPs(aaaa)...)
					if len(ips) > 0 {
						fmt.Printf("    resolve: %s\n", strings.Join(ips, ", "))
					}
				}
			}
		}
	}

	tlsRptName := "_smtp._tls." + domain
	tlsRpt, err := queryType(ctx, client, resolver, tlsRptName, dns.TypeTXT)
	if err != nil {
		fmt.Printf("TLS-RPT: error: %v\n", err)
	} else {
		v := findTXTContains(tlsRpt, "v=TLSRPTv1")
		if v == "" {
			fmt.Println("TLS-RPT: niet gevonden")
		} else {
			fmt.Printf("TLS-RPT: %s\n", v)
		}
	}

	mtaStsName := "_mta-sts." + domain
	mtaSts, err := queryType(ctx, client, resolver, mtaStsName, dns.TypeTXT)
	if err != nil {
		fmt.Printf("MTA-STS: error: %v\n", err)
	} else {
		v := findTXTContains(mtaSts, "v=STSv1")
		if v == "" {
			fmt.Println("MTA-STS: niet gevonden")
		} else {
			fmt.Printf("MTA-STS: %s\n", v)
		}
	}

	return nil
}

func runAllDNS(ctx context.Context, client *dns.Client, resolver, domain string) error {
	type q struct {
		name  string
		qtype uint16
	}
	queries := []q{
		{"A", dns.TypeA},
		{"AAAA", dns.TypeAAAA},
		{"CNAME", dns.TypeCNAME},
		{"MX", dns.TypeMX},
		{"NS", dns.TypeNS},
		{"TXT", dns.TypeTXT},
		{"SOA", dns.TypeSOA},
		{"CAA", dns.TypeCAA},
	}

	for _, qu := range queries {
		fmt.Printf("\n-- %s --\n", qu.name)
		printRRs(queryType(ctx, client, resolver, domain, qu.qtype))
	}

	fmt.Printf("\n-- SRV (bekende services) --\n")
	if err := runCommonSRV(ctx, client, resolver, domain); err != nil {
		fmt.Printf("SRV: error: %v\n", err)
	}

	fmt.Printf("\n-- MAIL CHECKS --\n")
	return mailChecks(ctx, client, resolver, domain)
}


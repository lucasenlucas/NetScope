package main

import (
	"context"
	"fmt"
	"strings"
)

func runUnifiedAnalysis(o options) {
	fmt.Printf("\n🚀 NetScope Analysis gestart voor doelwit: %s\n", o.domain)
	fmt.Println(strings.Repeat("=", 60))

	ctx := context.Background()

	// DNS & Mail Analyser routing
	runDNS := false
	if o.inf || o.n || o.whois || o.subs || o.a || o.aaaa || o.cname || o.mx || o.ns || o.txt || o.soa || o.caa || o.srv || o.records != "" || o.resolve != "" || o.dnssec {
		runDNS = true
	}

	if runDNS {
		fmt.Println("\n🔍 [MODULE: DNS & MAIL SECURITY]")
		runDNSAnalysis(ctx, o)
	}

	// Web Security routing
	runWeb := false
	if o.httpCheck || o.tlsCheck || o.headersCheck || o.cacheCheck || o.fingerCheck || o.portsCheck || o.pathsCheck || o.corsCheck || o.cookieCheck || o.techCheck || o.crawlerCheck || o.methodCheck {
		runWeb = true
	}

	if runWeb {
		fmt.Println("\n🛡️  [MODULE: WEB SECURITY & ANALYSIS]")
		runWebAnalysis(o)
	}

	// Vulnerability & Brute-Force routing
	runVuln := false
	if o.dirCheck || o.paramsCheck || o.cmsCheck || o.bruteCheck {
		runVuln = true
	}
	if runVuln {
		// HARDCODED PASSWORD CHECK
		const secretKey = "NetScope-Vuln-2026"
		if o.key != secretKey {
			fmt.Println("\n❌ [ERROR: TOEGANG GEWEIGERD]")
			fmt.Println("Deze module is beveiligd. Gebruik de '-key' flag met de juiste sleutel.")
			fmt.Println("Neem contact op met de beheerder voor de licentiesleutel.")
			return
		}

		fmt.Println("\n🔥 [MODULE: VULNERABILITY & BRUTE-FORCING]")
		runVulnAnalysis(o)
	}

	// Metrics / Measure routing
	if o.measure {
		fmt.Println("\n⚡ [MODULE: L7 METRICS & MEASURE]")
		// the measure logic is technically merged into web_analysis,
		// but since we split it, let's keep it simple for now or call runWebAnalysis again
		// with measure flag handled. (We will handle this in web_analysis directly later).
		// We actually moved measure logic to runWebAnalysis in our previous rewrite,
		// so we just call it if only measure is passed.
		if !runWeb {
			runWebAnalysis(o)
		}
	}

	fmt.Println("\n✅ Analysis Voltooid.")
}

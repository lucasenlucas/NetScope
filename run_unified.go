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
	if o.httpCheck || o.tlsCheck || o.headersCheck || o.cacheCheck || o.fingerCheck || o.portsCheck || o.pathsCheck || o.corsCheck || o.cookieCheck || o.bruteCheck || o.techCheck || o.crawlerCheck || o.methodCheck {
		runWeb = true
	}

	if runWeb {
		fmt.Println("\n🛡️  [MODULE: WEB SECURITY & ANALYSIS]")
		runWebAnalysis(o)
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

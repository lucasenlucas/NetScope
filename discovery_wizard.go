package main

import (
	"fmt"
	"os"
)

func runDiscoveryWizard(o options) {
	fmt.Println("Welkom bij de NetScope Discovery Wizard!")
	fmt.Println("Ik help je om snel de juiste scan-instellingen te kiezen.")

	// Step 1: Target Domain
	domainLabel := "Op welk domein wil je de analyse uitvoeren?"
	domainExpl := "Het domein is het adres van de website (bijv. example.com). Voer de naam in zonder http:// of https://."
	domainChatGPT := "Ik ben bezig met een security-analyse van mijn eigen omgeving. Hoe identificeer ik het hoofddomein van een webserver voor technische scouting?"

	for o.domain == "" {
		o.domain = promptInput(domainLabel, domainExpl, domainChatGPT)
		if o.domain == "" {
			fmt.Println("[!] Oeps! Je moet wel een domein opgeven om verder te gaan.")
		}
	}
	o.domain = normalizeDomain(o.domain)

	// Step 2: Discovery Mode Selection
	discoveryOptions := []string{
		"Basis Scan (DNS, Security Headers, WHOIS)",
		"Directory & File Discovery (Bestandsscan)",
		"Parameter Discovery (Verborgen parameters)",
		"CMS & Plugin Analysis (WordPress/Joomla)",
		"Full Discovery (Alles hierboven)",
	}

	choice := promptMenu("Welke analyse-modus wil je starten?", discoveryOptions)

	switch choice {
	case 0:
		o.inf = true
		o.headersCheck = true
		o.whois = true
	case 1:
		o.dirCheck = true
	case 2:
		o.paramsCheck = true
	case 3:
		o.cmsCheck = true
	case 4:
		o.inf = true
		o.dirCheck = true
		o.paramsCheck = true
		o.cmsCheck = true
		o.headersCheck = true
	}

	// Step 3: Final Confirmation
	fmt.Printf("\n--- Configuratie Compleet ---\n")
	fmt.Printf("Doelwit:  %s\n", o.domain)
	fmt.Printf("Modus:    %s\n", discoveryOptions[choice])

	confirm := promptInput("Alles naar wens? (druk op Enter om te starten, of 'n' om te stoppen)", "", "")
	if confirm == "n" || confirm == "N" {
		fmt.Println("Analyse afgebroken. Tot de volgende keer!")
		os.Exit(0)
	}

	fmt.Println("\n🚀 We gaan beginnen! NetScope modules worden geladen...")
	runUnifiedAnalysis(o)
}

package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func printBanner(version string) {
	banner := `
    _   __     __  _____                     
   / | / /__  / /_/ ___/_________  ____  ___ 
  /  |/ / _ \/ __/\__ \/ ___/ __ \/ __ \/ _ \
 / /|  /  __/ /_ ___/ / /__/ /_/ / /_/ /  __/
/_/ |_/\___/\__//____/\___/\____/ .___/\___/ 
                               /_/           
`
	fmt.Println(banner)
	fmt.Println("NetScope is made by Lucas Mangroelal | lucasmangroelal.nl")
	fmt.Printf("Version: %s | Platform: %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
	fmt.Println("💡 [TIP]: Gebruik '-dir -tech' voor een diepgaande discovery op WordPress sites!")
	fmt.Println("")
}

func promptInput(label, explanation, chatGPTPrompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("\n[?] %s\n", label)
	if explanation != "" {
		fmt.Printf("    💡 %s\n", explanation)
	}
	fmt.Printf("    (Type 'help' voor een ChatGPT prompt, of laat leeg voor overstappen)\n")
	fmt.Print("    > ")

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if strings.ToLower(input) == "help" {
		fmt.Println("\n--- ChatGPT Prompt (Kopieer dit) ---")
		fmt.Println(chatGPTPrompt)
		fmt.Println("------------------------------------")
		return promptInput(label, explanation, chatGPTPrompt)
	}

	return input
}

func promptMenu(title string, options []string) int {
	fmt.Printf("\n--- %s ---\n", title)
	for i, opt := range options {
		fmt.Printf("[%d] %s\n", i+1, opt)
	}
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("Selecteer een optie (1-%d): ", len(options))
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		var choice int
		_, err := fmt.Sscanf(input, "%d", &choice)
		if err == nil && choice >= 1 && choice <= len(options) {
			return choice - 1
		}
		fmt.Println("[!] Ongeldige keuze, probeer het opnieuw.")
	}
}

type flagHelp struct {
	flag string
	desc string
}

func printBoxedSection(title string, flags []flagHelp) {
	// Calculate max widths
	maxFlagLen := 0
	for _, f := range flags {
		if len(f.flag) > maxFlagLen {
			maxFlagLen = len(f.flag)
		}
	}
	// Give a little padding
	maxFlagLen += 2

	// Set console width bound (e.g. 90 chars total)
	totalWidth := 90
	descWidth := totalWidth - maxFlagLen - 7 // 7 for borders like "│ " " │ " " │"

	fmt.Fprintf(os.Stderr, "┌%s┐\n", strings.Repeat("─", totalWidth-2))

	// Title centered or left aligned
	titleLine := fmt.Sprintf(" %s ", title)
	padding := totalWidth - 2 - len(titleLine)
	if padding < 0 {
		padding = 0
	}
	fmt.Fprintf(os.Stderr, "│%s%s│\n", titleLine, strings.Repeat(" ", padding))
	fmt.Fprintf(os.Stderr, "├%s┬%s┤\n", strings.Repeat("─", maxFlagLen+2), strings.Repeat("─", totalWidth-maxFlagLen-5))

	for _, f := range flags {
		flagStr := fmt.Sprintf(" %-*s ", maxFlagLen, f.flag)

		// Wrap desc
		words := strings.Split(f.desc, " ")
		var lines []string
		currentLine := ""
		for _, w := range words {
			if len(currentLine)+len(w)+1 > descWidth {
				lines = append(lines, currentLine)
				currentLine = w
			} else {
				if currentLine == "" {
					currentLine = w
				} else {
					currentLine += " " + w
				}
			}
		}
		if currentLine != "" {
			lines = append(lines, currentLine)
		}

		for i, line := range lines {
			if i == 0 {
				fmt.Fprintf(os.Stderr, "│%s│ %-*s │\n", flagStr, descWidth, line)
			} else {
				fmt.Fprintf(os.Stderr, "│%s│ %-*s │\n", strings.Repeat(" ", maxFlagLen+2), descWidth, line)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "└%s┴%s┘\n", strings.Repeat("─", maxFlagLen+2), strings.Repeat("─", totalWidth-maxFlagLen-5))
}

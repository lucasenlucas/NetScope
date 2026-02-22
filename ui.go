package main

import (
	"fmt"
	"os"
	"strings"
)

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

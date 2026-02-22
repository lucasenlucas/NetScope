package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const repoAPI = "https://api.github.com/repos/lucasenlucas/NetScope/releases/latest"

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func checkForUpdates(currentVersion string) (*ghRelease, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", repoAPI, nil)
	req.Header.Set("User-Agent", "NetScope-Updater/1.0")

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fout bij het bereiken van GitHub API: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("github api gaf statuscode %d", res.StatusCode)
	}

	var release ghRelease
	if err := json.NewDecoder(res.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("fout bij parsen van release data: %v", err)
	}

	return &release, nil
}

func runCheckUpdate() {
	fmt.Println("🔍 Controleren op updates...")
	release, err := checkForUpdates("v" + version)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		return
	}

	targetVer := "v" + version
	if release.TagName == targetVer {
		fmt.Printf("✅ Je gebruikt de nieuwste versie: %s\n", version)
	} else {
		fmt.Printf("⚠️  Er is een nieuwere versie beschikbaar!\n")
		fmt.Printf("Huidig: %s  |  Nieuw: %s\n", targetVer, release.TagName)
		fmt.Printf("Gebruik 'netscope --update' om te installeren.\n")
	}
}

func runAutoUpdate() {
	fmt.Println("⏳ Controleren op de nieuwste versie...")
	release, err := checkForUpdates("v" + version)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		return
	}

	targetVer := "v" + version
	if release.TagName == targetVer {
		fmt.Printf("✅ Je bent al up-to-date (%s).\n", version)
		return
	}

	fmt.Printf("⬇️  Update gevonden: %s (Huidig: %s)\n", release.TagName, targetVer)

	// Determine asset name (e.g., netscope_darwin_arm64, netscope_linux_amd64 etc)
	expectedPrefix := fmt.Sprintf("netscope_%s_%s", runtime.GOOS, runtime.GOARCH)
	var downloadURL string

	for _, asset := range release.Assets {
		if strings.HasPrefix(asset.Name, expectedPrefix) {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		fmt.Printf("❌ Kan geen geschikte binary file vinden voor jouw platform (%s/%s) in deze release.\n", runtime.GOOS, runtime.GOARCH)
		return
	}

	fmt.Printf("📥 Downloaden van: %s...\n", downloadURL)
	client := &http.Client{Timeout: 60 * time.Second}
	req, _ := http.NewRequest("GET", downloadURL, nil)
	req.Header.Set("User-Agent", "NetScope-Updater/1.0")

	res, err := client.Do(req)
	if err != nil || res.StatusCode != 200 {
		fmt.Printf("❌ Fout bij downloaden van nieuwe binary: %v\n", err)
		return
	}
	defer res.Body.Close()

	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("❌ Kan huidige executable pad niet bepalen: %v\n", err)
		return
	}

	// Follow symlinks
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		// Ignore
	}

	tempFile := exePath + ".tmp"
	out, err := os.OpenFile(tempFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Printf("❌ Kan tijdelijk bestand niet schrijven (geen permissies?): %v\n", err)
		return
	}

	_, err = io.Copy(out, res.Body)
	out.Close()
	if err != nil {
		fmt.Printf("❌ Download onderbroken: %v\n", err)
		_ = os.Remove(tempFile)
		return
	}

	// Rename temp file to current executable
	err = os.Rename(tempFile, exePath)
	if err != nil {
		// Try moving current first?
		oldFile := exePath + ".old"
		os.Rename(exePath, oldFile)
		err = os.Rename(tempFile, exePath)
		if err != nil {
			fmt.Printf("❌ Fout bij overschrijven van executable: %v\n", err)
			return
		}
		os.Remove(oldFile)
	}

	fmt.Printf("🎉 NetScope is succesvol geupdate naar %s!\n", release.TagName)

	// Ophalen van permissies, hoewel we 0755 specificeerde, voor de zekerheid:
	_ = os.Chmod(exePath, 0755)

	// Optioneel: execute "netscope --version" to show success
	cmd := exec.Command(exePath, "--version")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

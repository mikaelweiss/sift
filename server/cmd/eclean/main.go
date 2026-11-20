package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"time"

	"github.com/mikaelweiss/eclean/server/internal/config"
	"github.com/mikaelweiss/eclean/server/internal/db"
)

var Version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("eclean %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
	case "status":
		runStatus(os.Args[2:])
	case "pair":
		runPair(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: eclean <serve|pair|status|version> [flags]")
}

func resolveDataDir(flagDir string) string {
	if flagDir != "" {
		return flagDir
	}
	dir, err := config.DefaultDataDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	return dir
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	_ = fs.Parse(args)

	dir := resolveDataDir(*dataDir)
	store, err := db.Open(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	devices, _ := store.CountPairedDevices()
	fingerprint, _, _ := store.GetRawSetting("tls_fingerprint")
	listenPort, _, _ := store.GetRawSetting("listen_port")
	if listenPort == "" {
		listenPort = fmt.Sprintf("%d", config.DefaultListenPort)
	}

	out := map[string]any{
		"version":         Version,
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"data_dir":        dir,
		"paired_devices":  devices,
		"tls_fingerprint": fingerprint,
		"listen_port":     listenPort,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func runPair(args []string) {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	_ = fs.Parse(args)

	dir := resolveDataDir(*dataDir)
	store, err := db.Open(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	code, err := generateSixDigitCode()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	sum := sha256.Sum256([]byte(code))
	if err := store.CreatePairingCode(hex.EncodeToString(sum[:]), 10*time.Minute); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Pairing code (valid 10 minutes): %s\n", code)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	_ = fs.Parse(args)

	dir := resolveDataDir(*dataDir)
	store, err := db.Open(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	fmt.Printf("eclean %s initialized at %s\n", Version, dir)
}

func generateSixDigitCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

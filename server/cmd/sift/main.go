package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/mikaelweiss/sift/server/internal/abuse"
	"github.com/mikaelweiss/sift/server/internal/api"
	"github.com/mikaelweiss/sift/server/internal/classifier"
	"github.com/mikaelweiss/sift/server/internal/config"
	"github.com/mikaelweiss/sift/server/internal/db"
	"github.com/mikaelweiss/sift/server/internal/imap"
)

var Version = "0.1.11"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("sift %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
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
	fmt.Fprintln(os.Stderr, "Usage: sift <serve|pair|status|version> [flags]")
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
	port := fs.Int("port", config.DefaultListenPort, "HTTPS listen port")
	_ = fs.Parse(args)

	dir := resolveDataDir(*dataDir)
	store, err := db.Open(dir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	cert, fingerprint, err := api.LoadOrGenerateTLS(dir)
	if err != nil {
		log.Fatalf("init TLS: %v", err)
	}
	_ = store.SetRawSetting("tls_fingerprint", fingerprint, false)
	_ = store.SetRawSetting("listen_port", strconv.Itoa(*port), false)

	hub := api.NewHub()
	engine := classifier.NewEngine(store, nil)
	abuseSvc := abuse.NewService(store, nil, nil)
	watcher := imap.NewWatcher(store, engine, abuseSvc)
	scanner := imap.NewScanner(store, engine, abuseSvc)
	apiServer := api.NewServer(store, watcher, scanner, abuseSvc, hub, Version, fingerprint)

	abuseSvc.OnQueueChanged = func(pendingCount int) {
		hub.Publish("abuse_queue", map[string]int{"pending_count": pendingCount})
	}
	watcher.OnEventProcessed = func(ev db.EmailEvent) {
		hub.Publish("email_processed", ev)
	}
	watcher.OnStatusChanged = func(_ imap.StatusSnapshot) {
		hub.Publish("health", apiServer.BuildHealthPayload())
	}
	scanner.OnProgress = func(job db.ScanJob) {
		hub.Publish("scan_progress", job)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go watcher.Run(ctx)

	httpServer := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", *port),
		Handler: apiServer.Handler(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 15 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	log.Printf("sift %s listening on https://0.0.0.0:%d (TLS SHA-256: %s)", Version, *port, fingerprint)
	if err := httpServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("https server error: %v", err)
	}
}

func generateSixDigitCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

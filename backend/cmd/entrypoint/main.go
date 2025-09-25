package main

import (
	"log"
	"os"
	"syscall"
	"time"
)

// A tiny entrypoint that ensures sane env defaults and then execs the main binary.
func main() {
	if os.Getenv("PORT") == "" {
		// Default to 8080 if platform doesn't inject PORT
		_ = os.Setenv("PORT", "8080")
	}

	// Optional startup delay for Coolify compatibility
	if delay := os.Getenv("STARTUP_DELAY"); delay != "" {
		if d, err := time.ParseDuration(delay); err == nil && d > 0 {
			log.Printf("Applying startup delay: %v", d)
			time.Sleep(d)
		}
	}

	target := os.Getenv("BACKEND_BINARY")
	if target == "" {
		target = "/app/main"
	}
	if err := syscall.Exec(target, []string{target}, os.Environ()); err != nil {
		log.Fatalf("failed to exec %s: %v", target, err)
	}
}

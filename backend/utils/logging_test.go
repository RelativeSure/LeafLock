package utils

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

func TestEnsureInitialized(t *testing.T) {
	// reset global loggers
	DebugLogger, InfoLogger, WarnLogger, ErrorLogger = nil, nil, nil, nil

	// capture output to avoid polluting test logs
	oldStdout, oldStderr := os.Stdout, os.Stderr
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		_ = stderrR.Close()
		_ = stderrW.Close()
	}()

	os.Stdout = stdoutW
	os.Stderr = stderrW

	ensureInitialized()

	if InfoLogger == nil || ErrorLogger == nil || WarnLogger == nil || DebugLogger == nil {
		t.Fatal("ensureInitialized should create all loggers when they are nil")
	}
}

func TestLevelFromMessage(t *testing.T) {
	tests := []struct {
		msg      string
		expected LogLevel
	}{
		{"all good", LevelInfo},
		{"warning: disk usage high", LevelWarn},
		{"error connecting to db", LevelError},
		{"fatal: unrecoverable", LevelFatal},
		{"debug details", LevelDebug},
		{"❌ failure", LevelError},
		{"⚠️ caution", LevelWarn},
	}

	for _, tc := range tests {
		if got := levelFromMessage(tc.msg); got != tc.expected {
			t.Fatalf("levelFromMessage(%q) = %v, want %v", tc.msg, got, tc.expected)
		}
	}
}

func TestShouldLogRespectsLevel(t *testing.T) {
	// configure level to WARN
	currentLogLevel = LevelWarn
	if shouldLog(LevelInfo) {
		t.Fatalf("INFO should not log when level is WARN")
	}
	if !shouldLog(LevelError) {
		t.Fatalf("ERROR should log when level is WARN")
	}
}

func TestParseLogLevelFallback(t *testing.T) {
	_ = os.Unsetenv("LOG_LEVEL")
	_ = os.Unsetenv("LOGLEVEL")
	level, err := parseConfiguredLogLevel()
	if err != nil || level != LevelInfo {
		t.Fatalf("expected default LevelInfo, got %v err=%v", level, err)
	}

	if err := os.Setenv("LOG_LEVEL", "debug"); err != nil {
		t.Fatalf("Failed to set LOG_LEVEL: %v", err)
	}
	defer func() { _ = os.Unsetenv("LOG_LEVEL") }()
	level, err = parseConfiguredLogLevel()
	if err != nil || level != LevelDebug {
		t.Fatalf("expected LevelDebug, got %v err=%v", level, err)
	}

	if err := os.Setenv("LOG_LEVEL", "invalid"); err != nil {
		t.Fatalf("Failed to set LOG_LEVEL: %v", err)
	}
	level, err = parseConfiguredLogLevel()
	if err == nil || level != LevelInfo {
		t.Fatalf("expected fallback LevelInfo with error, got level=%v err=%v", level, err)
	}
}

func TestLevelWriterFiltersMessages(t *testing.T) {
	var buf bytes.Buffer
	w := newLevelWriter(LevelInfo, &buf)
	logger := log.New(w, "", 0)

	currentLogLevel = LevelWarn

	logger.Println("info: should not write")
	if buf.Len() != 0 {
		t.Fatalf("expected INFO message to be filtered")
	}
}

func TestLogHelpers(t *testing.T) {
	var infoBuf, warnBuf bytes.Buffer
	DebugLogger = log.New(&infoBuf, "", 0)
	InfoLogger = log.New(&infoBuf, "", 0)
	WarnLogger = log.New(&warnBuf, "", 0)
	ErrorLogger = log.New(&warnBuf, "", 0)

	currentLogLevel = LevelDebug
	LogInfo("info message", "key", 1)
	LogWarn("warn message")
	LogDebug("debug message")
	LogError("context", fmt.Errorf("boom"))

	if !strings.Contains(infoBuf.String(), "info message") || !strings.Contains(infoBuf.String(), "debug message") {
		t.Fatalf("expected info/debug logs in buffer, got %q", infoBuf.String())
	}
	if !strings.Contains(warnBuf.String(), "warn message") || !strings.Contains(warnBuf.String(), "boom") {
		t.Fatalf("expected warn/error logs in buffer, got %q", warnBuf.String())
	}

	if name := CurrentLogLevelName(); name == "" {
		t.Fatalf("expected current log level name, got empty string")
	}
}

func TestLogRequestError(t *testing.T) {
	app := fiber.New()
	c := app.AcquireCtx(&fasthttp.RequestCtx{})
	defer app.ReleaseCtx(c)
	c.Locals("request_id", "req-123")
	c.Locals("user_id", uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"))

	var errBuf bytes.Buffer
	ErrorLogger = log.New(&errBuf, "", 0)
	InfoLogger = log.New(io.Discard, "", 0)
	WarnLogger = log.New(io.Discard, "", 0)
	DebugLogger = log.New(io.Discard, "", 0)
	currentLogLevel = LevelInfo

	LogRequestError(c, "test context", fmt.Errorf("failure"))
	if !strings.Contains(errBuf.String(), "failure") || !strings.Contains(errBuf.String(), "req-123") {
		t.Fatalf("expected structured error log, got %q", errBuf.String())
	}
}

func TestRootLogWriter(t *testing.T) {
	var infoBuf, errorBuf bytes.Buffer
	w := &rootLogWriter{infoOut: &infoBuf, errorOut: &errorBuf}
	currentLogLevel = LevelDebug

	if _, err := w.Write([]byte("INFO: hello")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(infoBuf.String(), "INFO") {
		t.Fatalf("expected info output, got %q", infoBuf.String())
	}

	if _, err := w.Write([]byte("WARNING: caution")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(errorBuf.String(), "WARNING") {
		t.Fatalf("expected warning routed to error buffer, got %q", errorBuf.String())
	}
}

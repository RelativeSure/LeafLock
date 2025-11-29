// Package utils provides common utility functions for the application.
// Includes structured logging, validation helpers, and shared functionality across modules.
package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Global logger variables for structured logging across the application
// Separate loggers for different severity levels with appropriate output streams
var (
	DebugLogger *log.Logger
	InfoLogger  *log.Logger
	WarnLogger  *log.Logger
	ErrorLogger *log.Logger

	currentLogLevel = LevelInfo
)

// LogLevel represents the severity threshold for log messages
type LogLevel int

// Supported log levels ordered by verbosity
const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

// levelLabels maps log levels to human-readable names
var levelLabels = map[LogLevel]string{
	LevelDebug: "DEBUG",
	LevelInfo:  "INFO",
	LevelWarn:  "WARN",
	LevelError: "ERROR",
	LevelFatal: "FATAL",
}

// InitLogging initializes structured logging with separate stdout/stderr streams
func InitLogging() {
	level, err := parseConfiguredLogLevel()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Invalid LOG_LEVEL value '%s'; defaulting to INFO\n", err.Error())
	}
	currentLogLevel = level

	flags := log.Ldate | log.Ltime | log.Lshortfile

	DebugLogger = log.New(newLevelWriter(LevelDebug, os.Stdout), "DEBUG: ", flags)
	InfoLogger = log.New(newLevelWriter(LevelInfo, os.Stdout), "INFO: ", flags)
	WarnLogger = log.New(newLevelWriter(LevelWarn, os.Stderr), "WARN: ", flags)
	ErrorLogger = log.New(newLevelWriter(LevelError, os.Stderr), "ERROR: ", flags)

	log.SetOutput(&rootLogWriter{infoOut: os.Stdout, errorOut: os.Stderr})
	log.SetPrefix("SYSTEM: ")
	log.SetFlags(flags)
}

// LogError logs errors with context to stderr
func LogError(context string, err error, metadata ...interface{}) {
	if err != nil {
		ensureInitialized()
		args := []interface{}{context, err}
		args = append(args, metadata...)
		ErrorLogger.Println(args...)
	}
}

// LogInfo logs informational messages to stdout
func LogInfo(message string, metadata ...interface{}) {
	ensureInitialized()
	args := []interface{}{message}
	args = append(args, metadata...)
	InfoLogger.Println(args...)
}

// LogWarn logs warnings to stderr respecting the configured level
func LogWarn(message string, metadata ...interface{}) {
	ensureInitialized()
	args := []interface{}{message}
	args = append(args, metadata...)
	WarnLogger.Println(args...)
}

// LogDebug logs verbose diagnostic messages when enabled
func LogDebug(message string, metadata ...interface{}) {
	ensureInitialized()
	args := []interface{}{message}
	args = append(args, metadata...)
	DebugLogger.Println(args...)
}

// LogRequestError logs errors with request context to stderr
func LogRequestError(c *fiber.Ctx, context string, err error, metadata ...interface{}) {
	if err != nil {
		ensureInitialized()
		requestID, _ := c.Locals("request_id").(string)
		userID, _ := c.Locals("user_id").(uuid.UUID)

		args := []interface{}{
			"request_id", requestID,
			"user_id", userID.String(),
			"method", c.Method(),
			"path", c.Path(),
			"ip", c.IP(),
			"context", context,
			"error", err,
		}
		args = append(args, metadata...)
		ErrorLogger.Println(args...)
	}
}

// CurrentLogLevelName returns the active log level label (e.g. INFO, WARN).
func CurrentLogLevelName() string {
	if name, ok := levelLabels[currentLogLevel]; ok {
		return name
	}
	return "INFO"
}

// shouldLog verifies whether the provided level is emitted given the configured threshold.
func shouldLog(level LogLevel) bool {
	return level >= currentLogLevel
}

// ensureInitialized guarantees loggers are available even if InitLogging wasn't invoked explicitly.
func ensureInitialized() {
	if InfoLogger != nil && ErrorLogger != nil && WarnLogger != nil && DebugLogger != nil {
		return
	}
	InitLogging()
}

// parseConfiguredLogLevel resolves the desired log level from environment variables.
func parseConfiguredLogLevel() (LogLevel, error) {
	value := strings.TrimSpace(os.Getenv("LOG_LEVEL"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("LOGLEVEL"))
	}
	if value == "" {
		return LevelInfo, nil
	}
	if level, ok := parseLogLevel(value); ok {
		return level, nil
	}
	return LevelInfo, fmt.Errorf("%s", value)
}

// parseLogLevel converts a textual level into the matching LogLevel.
func parseLogLevel(value string) (LogLevel, bool) {
	switch strings.ToLower(value) {
	case "debug", "trace":
		return LevelDebug, true
	case "info", "information":
		return LevelInfo, true
	case "warn", "warning":
		return LevelWarn, true
	case "error", "err":
		return LevelError, true
	case "fatal", "panic", "critical":
		return LevelFatal, true
	default:
		return LevelInfo, false
	}
}

// levelFromMessage attempts to infer severity from the log payload when using the standard logger.
func levelFromMessage(msg string) LogLevel {
	upper := strings.ToUpper(msg)
	switch {
	case strings.Contains(upper, "FATAL"), strings.Contains(msg, "💥"):
		return LevelFatal
	case strings.Contains(upper, "ERROR"), strings.Contains(upper, "FAILED"), strings.Contains(msg, "❌"):
		return LevelError
	case strings.Contains(upper, "WARN"), strings.Contains(upper, "WARNING"), strings.Contains(msg, "⚠️"):
		return LevelWarn
	case strings.Contains(upper, "DEBUG"):
		return LevelDebug
	default:
		return LevelInfo
	}
}

// levelWriter filters log output based on the configured threshold.
type levelWriter struct {
	level LogLevel
	out   io.Writer
}

func newLevelWriter(level LogLevel, out io.Writer) io.Writer {
	return &levelWriter{level: level, out: out}
}

func (w *levelWriter) Write(p []byte) (int, error) {
	if !shouldLog(w.level) {
		return len(p), nil
	}
	return w.out.Write(p)
}

// rootLogWriter routes standard library log output to stdout/stderr with filtering.
type rootLogWriter struct {
	infoOut  io.Writer
	errorOut io.Writer
}

func (w *rootLogWriter) Write(p []byte) (int, error) {
	level := levelFromMessage(string(p))
	if !shouldLog(level) {
		return len(p), nil
	}
	if level >= LevelWarn {
		return w.errorOut.Write(p)
	}
	return w.infoOut.Write(p)
}

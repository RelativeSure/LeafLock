package utils

import (
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// ErrorContext provides structured error information with stack traces and request context
type ErrorContext struct {
	Timestamp   time.Time              `json:"timestamp"`
	Level       string                 `json:"level"`
	Message     string                 `json:"message"`
	Error       string                 `json:"error,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	Method      string                 `json:"method,omitempty"`
	Path        string                 `json:"path,omitempty"`
	IP          string                 `json:"ip,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	StatusCode  int                    `json:"status_code,omitempty"`
	Stack       []StackFrame           `json:"stack,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Environment string                 `json:"environment,omitempty"`
}

// StackFrame represents a single frame in the call stack
type StackFrame struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

// CaptureStackTrace captures the current stack trace
func CaptureStackTrace(skip int) []StackFrame {
	const maxDepth = 32
	var pcs [maxDepth]uintptr
	n := runtime.Callers(skip+2, pcs[:])

	frames := make([]StackFrame, 0, n)
	for i := 0; i < n; i++ {
		frame, _ := runtime.CallersFrames([]uintptr{pcs[i]}).Next()
		frames = append(frames, StackFrame{
			Function: frame.Function,
			File:     frame.File,
			Line:     frame.Line,
		})
	}
	return frames
}

// LogErrorWithStack logs an error with full stack trace and context
func LogErrorWithStack(context string, err error, metadata map[string]interface{}) {
	if err == nil {
		return
	}

	errCtx := ErrorContext{
		Timestamp: time.Now(),
		Level:     "ERROR",
		Message:   context,
		Error:     err.Error(),
		Stack:     CaptureStackTrace(1),
		Metadata:  metadata,
	}

	logStructured(errCtx)
}

// LogErrorWithRequestContext logs an error with full request context and stack trace
func LogErrorWithRequestContext(c *fiber.Ctx, context string, err error, metadata map[string]interface{}) {
	if err == nil {
		return
	}

	requestID, _ := c.Locals("request_id").(string)
	userID, _ := c.Locals("user_id").(uuid.UUID)

	errCtx := ErrorContext{
		Timestamp:   time.Now(),
		Level:       "ERROR",
		Message:     context,
		Error:       err.Error(),
		RequestID:   requestID,
		UserID:      userID.String(),
		Method:      c.Method(),
		Path:        c.Path(),
		IP:          ClientIP(c),
		UserAgent:   c.Get("User-Agent"),
		StatusCode:  c.Response().StatusCode(),
		Stack:       CaptureStackTrace(1),
		Metadata:    metadata,
		Environment: GetEnvironment(),
	}

	logStructured(errCtx)
}

// LogWarningWithContext logs a warning with context
func LogWarningWithContext(c *fiber.Ctx, message string, metadata map[string]interface{}) {
	requestID, _ := c.Locals("request_id").(string)
	userID, _ := c.Locals("user_id").(uuid.UUID)

	warnCtx := ErrorContext{
		Timestamp:   time.Now(),
		Level:       "WARN",
		Message:     message,
		RequestID:   requestID,
		UserID:      userID.String(),
		Method:      c.Method(),
		Path:        c.Path(),
		IP:          ClientIP(c),
		Metadata:    metadata,
		Environment: GetEnvironment(),
	}

	logStructured(warnCtx)
}

// LogInfoWithContext logs an info message with context
func LogInfoWithContext(message string, metadata map[string]interface{}) {
	infoCtx := ErrorContext{
		Timestamp:   time.Now(),
		Level:       "INFO",
		Message:     message,
		Metadata:    metadata,
		Environment: GetEnvironment(),
	}

	logStructured(infoCtx)
}

// LogDebugWithContext logs a debug message with context
func LogDebugWithContext(message string, metadata map[string]interface{}) {
	debugCtx := ErrorContext{
		Timestamp:   time.Now(),
		Level:       "DEBUG",
		Message:     message,
		Metadata:    metadata,
		Environment: GetEnvironment(),
	}

	logStructured(debugCtx)
}

// logStructured outputs a structured log entry in JSON format for production
// or human-readable format for development
func logStructured(ctx ErrorContext) {
	ensureInitialized()

	// In production, output JSON for log aggregation tools
	if IsProduction() {
		jsonBytes, err := json.Marshal(ctx)
		if err != nil {
			ErrorLogger.Printf("Failed to marshal log context: %v", err)
			return
		}

		// Route to appropriate logger based on level
		switch ctx.Level {
		case "ERROR", "FATAL":
			ErrorLogger.Printf("%s", string(jsonBytes))
		case "WARN":
			WarnLogger.Printf("%s", string(jsonBytes))
		case "DEBUG":
			DebugLogger.Printf("%s", string(jsonBytes))
		default:
			InfoLogger.Printf("%s", string(jsonBytes))
		}
	} else {
		// Development: human-readable format
		logHumanReadable(ctx)
	}
}

// logHumanReadable outputs a human-readable log entry for development
func logHumanReadable(ctx ErrorContext) {
	logLine := fmt.Sprintf("[%s] %s", ctx.Level, ctx.Message)

	if ctx.Error != "" {
		logLine += fmt.Sprintf(" | Error: %s", ctx.Error)
	}

	if ctx.RequestID != "" {
		logLine += fmt.Sprintf(" | RequestID: %s", ctx.RequestID)
	}

	if ctx.UserID != "" && ctx.UserID != "00000000-0000-0000-0000-000000000000" {
		logLine += fmt.Sprintf(" | UserID: %s", ctx.UserID)
	}

	if ctx.Method != "" && ctx.Path != "" {
		logLine += fmt.Sprintf(" | %s %s", ctx.Method, ctx.Path)
	}

	if ctx.IP != "" {
		logLine += fmt.Sprintf(" | IP: %s", ctx.IP)
	}

	if len(ctx.Metadata) > 0 {
		metaJSON, _ := json.Marshal(ctx.Metadata)
		logLine += fmt.Sprintf(" | Metadata: %s", string(metaJSON))
	}

	// Output to appropriate logger
	switch ctx.Level {
	case "ERROR", "FATAL":
		ErrorLogger.Println(logLine)
		// Print stack trace for errors
		if len(ctx.Stack) > 0 {
			ErrorLogger.Println("Stack trace:")
			for i, frame := range ctx.Stack {
				if i >= 10 { // Limit stack trace to 10 frames
					break
				}
				ErrorLogger.Printf("  %s\n    %s:%d", frame.Function, frame.File, frame.Line)
			}
		}
	case "WARN":
		WarnLogger.Println(logLine)
	case "DEBUG":
		DebugLogger.Println(logLine)
	default:
		InfoLogger.Println(logLine)
	}
}

// RecoverFromPanic recovers from panics and logs them with stack traces
func RecoverFromPanic(c *fiber.Ctx) {
	if r := recover(); r != nil {
		err := fmt.Errorf("panic: %v", r)

		metadata := map[string]interface{}{
			"panic_value": r,
		}

		LogErrorWithRequestContext(c, "Panic recovered", err, metadata)

		// Return 500 error to client
		_ = c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}
}

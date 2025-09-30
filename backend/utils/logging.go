package utils

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Global logger variables
var (
	InfoLogger  *log.Logger
	ErrorLogger *log.Logger
)

// InitLogging initializes structured logging with separate stdout/stderr streams
func InitLogging() {
	// Info logs go to stdout
	InfoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Error logs go to stderr
	ErrorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	// Configure default log package to use stderr for errors
	log.SetOutput(os.Stderr)
	log.SetPrefix("SYSTEM: ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

// LogError logs errors with context to stderr
func LogError(context string, err error, metadata ...interface{}) {
	if err != nil {
		args := []interface{}{context, err}
		args = append(args, metadata...)
		ErrorLogger.Println(args...)
	}
}

// LogInfo logs informational messages to stdout
func LogInfo(message string, metadata ...interface{}) {
	args := []interface{}{message}
	args = append(args, metadata...)
	InfoLogger.Println(args...)
}

// LogRequestError logs errors with request context to stderr
func LogRequestError(c *fiber.Ctx, context string, err error, metadata ...interface{}) {
	if err != nil {
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
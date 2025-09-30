package server

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// FiberResponseWriter adapts Fiber's context to http.ResponseWriter interface.
// This adapter enables compatibility with standard Go HTTP middleware and handlers
// that expect the http.ResponseWriter interface while using Fiber's high-performance context.
type FiberResponseWriter struct {
	ctx    *fiber.Ctx
	status int
	header http.Header
}

// NewFiberResponseWriter creates a new FiberResponseWriter adapter
func NewFiberResponseWriter(ctx *fiber.Ctx) *FiberResponseWriter {
	return &FiberResponseWriter{
		ctx:    ctx,
		status: 200,
		header: make(http.Header),
	}
}

// Header returns the header map that will be sent by WriteHeader.
// Implements http.ResponseWriter interface.
func (w *FiberResponseWriter) Header() http.Header {
	return w.header
}

// Write writes the data to the connection as part of an HTTP reply.
// Implements http.ResponseWriter interface.
func (w *FiberResponseWriter) Write(data []byte) (int, error) {
	// Copy headers to Fiber context
	for key, values := range w.header {
		for _, value := range values {
			w.ctx.Set(key, value)
		}
	}

	// Set status code if it was set
	if w.status != 200 {
		w.ctx.Status(w.status)
	}

	return w.ctx.Write(data)
}

// WriteHeader sends an HTTP response header with the provided status code.
// Implements http.ResponseWriter interface.
func (w *FiberResponseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
}
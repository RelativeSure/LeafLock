package metrics

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTP metrics
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "leaflock_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "leaflock_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1, 5, 10},
		},
		[]string{"method", "endpoint"},
	)

	// Application metrics
	activeUsers = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "leaflock_active_users",
			Help: "Number of currently active users",
		},
	)

	notesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "leaflock_notes_total",
			Help: "Total number of notes operations",
		},
		[]string{"operation"}, // create, update, delete
	)

	collaborationsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "leaflock_collaborations_active",
			Help: "Number of active collaborations",
		},
	)

	// WebSocket metrics
	websocketConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "leaflock_websocket_connections",
			Help: "Number of active WebSocket connections",
		},
	)

	// Database metrics
	dbConnectionsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "leaflock_db_connections_active",
			Help: "Number of active database connections",
		},
	)

	dbConnectionsIdle = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "leaflock_db_connections_idle",
			Help: "Number of idle database connections",
		},
	)

	dbQueriesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "leaflock_db_queries_total",
			Help: "Total number of database queries",
		},
		[]string{"operation"}, // select, insert, update, delete
	)

	// Redis metrics
	redisConnectionsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "leaflock_redis_connections_active",
			Help: "Number of active Redis connections",
		},
	)

	redisOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "leaflock_redis_operations_total",
			Help: "Total number of Redis operations",
		},
		[]string{"operation"}, // get, set, del, exists
	)

	// Error metrics
	errorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "leaflock_errors_total",
			Help: "Total number of errors",
		},
		[]string{"type", "component"}, // auth, database, redis, validation
	)

	// Backup metrics
	backupsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "leaflock_backups_total",
			Help: "Total number of backup operations",
		},
		[]string{"status"}, // success, failure
	)

	backupDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "leaflock_backup_duration_seconds",
			Help:    "Backup operation duration in seconds",
			Buckets: []float64{1, 5, 10, 30, 60, 300, 600},
		},
	)

	backupSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "leaflock_backup_size_bytes",
			Help: "Size of the last backup in bytes",
		},
	)
)

// PrometheusMiddleware creates a Fiber middleware for Prometheus metrics
func PrometheusMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Process request
		err := c.Next()

		// Record metrics
		duration := time.Since(start).Seconds()
		method := c.Method()
		path := c.Route().Path
		if path == "" {
			path = c.Path()
		}
		statusCode := strconv.Itoa(c.Response().StatusCode())

		httpRequestsTotal.WithLabelValues(method, path, statusCode).Inc()
		httpRequestDuration.WithLabelValues(method, path).Observe(duration)

		return err
	}
}

// UpdateActiveUsers updates the active users gauge
func UpdateActiveUsers(count int) {
	activeUsers.Set(float64(count))
}

// IncrementNoteOperation increments note operation counter
func IncrementNoteOperation(operation string) {
	notesTotal.WithLabelValues(operation).Inc()
}

// UpdateCollaborationsActive updates active collaborations gauge
func UpdateCollaborationsActive(count int) {
	collaborationsActive.Set(float64(count))
}

// UpdateWebSocketConnections updates WebSocket connections gauge
func UpdateWebSocketConnections(count int) {
	websocketConnections.Set(float64(count))
}

// UpdateDatabaseMetrics updates database connection metrics
func UpdateDatabaseMetrics(active, idle int) {
	dbConnectionsActive.Set(float64(active))
	dbConnectionsIdle.Set(float64(idle))
}

// IncrementDatabaseQuery increments database query counter
func IncrementDatabaseQuery(operation string) {
	dbQueriesTotal.WithLabelValues(operation).Inc()
}

// UpdateRedisConnections updates Redis connection metrics
func UpdateRedisConnections(count int) {
	redisConnectionsActive.Set(float64(count))
}

// IncrementRedisOperation increments Redis operation counter
func IncrementRedisOperation(operation string) {
	redisOperationsTotal.WithLabelValues(operation).Inc()
}

// IncrementError increments error counter
func IncrementError(errorType, component string) {
	errorsTotal.WithLabelValues(errorType, component).Inc()
}

// RecordBackup records backup metrics
func RecordBackup(status string, duration time.Duration, sizeBytes int64) {
	backupsTotal.WithLabelValues(status).Inc()
	backupDuration.Observe(duration.Seconds())
	if status == "success" {
		backupSize.Set(float64(sizeBytes))
	}
}

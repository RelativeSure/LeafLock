package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricSetters(t *testing.T) {
	UpdateActiveUsers(7)
	if got := testutil.ToFloat64(activeUsers); got != 7 {
		t.Fatalf("activeUsers gauge = %v, want 7", got)
	}

	UpdateCollaborationsActive(3)
	if got := testutil.ToFloat64(collaborationsActive); got != 3 {
		t.Fatalf("collaborationsActive = %v, want 3", got)
	}

	UpdateWebSocketConnections(5)
	if got := testutil.ToFloat64(websocketConnections); got != 5 {
		t.Fatalf("websocketConnections = %v, want 5", got)
	}

	UpdateDatabaseMetrics(4, 2)
	if got := testutil.ToFloat64(dbConnectionsActive); got != 4 {
		t.Fatalf("dbConnectionsActive = %v, want 4", got)
	}
	if got := testutil.ToFloat64(dbConnectionsIdle); got != 2 {
		t.Fatalf("dbConnectionsIdle = %v, want 2", got)
	}

	UpdateRedisConnections(9)
	if got := testutil.ToFloat64(redisConnectionsActive); got != 9 {
		t.Fatalf("redisConnectionsActive = %v, want 9", got)
	}
}

func TestMetricCounters(t *testing.T) {
	before := testutil.ToFloat64(notesTotal.WithLabelValues("create"))
	IncrementNoteOperation("create")
	if got := testutil.ToFloat64(notesTotal.WithLabelValues("create")); got != before+1 {
		t.Fatalf("notesTotal counter expected %v got %v", before+1, got)
	}

	before = testutil.ToFloat64(dbQueriesTotal.WithLabelValues("insert"))
	IncrementDatabaseQuery("insert")
	if got := testutil.ToFloat64(dbQueriesTotal.WithLabelValues("insert")); got != before+1 {
		t.Fatalf("dbQueriesTotal counter expected %v got %v", before+1, got)
	}

	before = testutil.ToFloat64(redisOperationsTotal.WithLabelValues("set"))
	IncrementRedisOperation("set")
	if got := testutil.ToFloat64(redisOperationsTotal.WithLabelValues("set")); got != before+1 {
		t.Fatalf("redisOperationsTotal counter expected %v got %v", before+1, got)
	}

	before = testutil.ToFloat64(errorsTotal.WithLabelValues("auth", "handler"))
	IncrementError("auth", "handler")
	if got := testutil.ToFloat64(errorsTotal.WithLabelValues("auth", "handler")); got != before+1 {
		t.Fatalf("errorsTotal counter expected %v got %v", before+1, got)
	}
}

func TestRecordBackupMetrics(t *testing.T) {
	beforeSuccess := testutil.ToFloat64(backupsTotal.WithLabelValues("success"))
	beforeFailure := testutil.ToFloat64(backupsTotal.WithLabelValues("failure"))

	RecordBackup("success", 2*time.Second, 1024)
	RecordBackup("failure", time.Second, 0)

	if got := testutil.ToFloat64(backupsTotal.WithLabelValues("success")); got != beforeSuccess+1 {
		t.Fatalf("expected success counter to increment, got %v", got)
	}
	if got := testutil.ToFloat64(backupsTotal.WithLabelValues("failure")); got != beforeFailure+1 {
		t.Fatalf("expected failure counter to increment, got %v", got)
	}
	if got := testutil.ToFloat64(backupSize); got != 1024 {
		t.Fatalf("backupSize gauge expected 1024, got %v", got)
	}
}


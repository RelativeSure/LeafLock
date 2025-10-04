package utils

import "testing"

func TestParseLogLevel(t *testing.T) {
	cases := map[string]LogLevel{
		"debug": LevelDebug,
		"INFO":  LevelInfo,
		"Warn":  LevelWarn,
		"error": LevelError,
		"fatal": LevelFatal,
	}

	for input, expected := range cases {
		got, ok := parseLogLevel(input)
		if !ok {
			t.Fatalf("expected %q to be recognized", input)
		}
		if got != expected {
			t.Fatalf("expected %s to map to %v, got %v", input, expected, got)
		}
	}
}

func TestParseConfiguredLogLevelFromEnv(t *testing.T) {
	cases := []struct {
		name          string
		logLevelEnv   string
		loglevelEnv   string
		expectedLevel LogLevel
		expectError   bool
	}{
		{"prioritizes LOG_LEVEL", "warn", "error", LevelWarn, false},
		{"fallback to LOGLEVEL", "", "error", LevelError, false},
		{"invalid value", "verbose", "", LevelInfo, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LOG_LEVEL", tc.logLevelEnv)
			t.Setenv("LOGLEVEL", tc.loglevelEnv)

			level, err := parseConfiguredLogLevel()
			if tc.expectError && err == nil {
				t.Fatalf("expected error for test %q", tc.name)
			}
			if !tc.expectError && err != nil {
				t.Fatalf("did not expect error for test %q, got %v", tc.name, err)
			}
			if level != tc.expectedLevel {
				t.Fatalf("expected level %v, got %v", tc.expectedLevel, level)
			}
		})
	}
}

func TestCurrentLogLevelName(t *testing.T) {
	t.Run("known level", func(t *testing.T) {
		original := currentLogLevel
		defer func() { currentLogLevel = original }()

		currentLogLevel = LevelError
		if name := CurrentLogLevelName(); name != "ERROR" {
			t.Fatalf("expected ERROR, got %s", name)
		}
	})

	t.Run("unknown level defaults to INFO", func(t *testing.T) {
		original := currentLogLevel
		defer func() { currentLogLevel = original }()

		currentLogLevel = LogLevel(42)
		if name := CurrentLogLevelName(); name != "INFO" {
			t.Fatalf("expected INFO fallback, got %s", name)
		}
	})
}

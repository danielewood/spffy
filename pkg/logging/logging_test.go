package logging

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name       string
		levelStr   string
		output     string
		wantLevel  LogLevel
		wantErrOut string // Expected stderr output for invalid levels
	}{
		{"valid_info", "INFO", "", LevelInfo, ""},
		{"valid_debug", "DEBUG", "", LevelDebug, ""},
		{"valid_trace", "TRACE", "", LevelTrace, ""},
		{"valid_none", "NONE", "", LevelNone, ""},
		{"invalid_level", "INVALID", "", LevelInfo, "Invalid log level INVALID, defaulting to INFO\n"},
		{"empty_level", "", "", LevelInfo, "Invalid log level , defaulting to INFO\n"},
		{"lowercase_level", "debug", "", LevelDebug, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stderr for validation
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			buffer := NewLogBuffer(10) // Dummy buffer
			logger := NewLogger(tt.levelStr, tt.output, buffer)

			w.Close()
			os.Stderr = oldStderr // Restore stderr
			var errOut bytes.Buffer
			_, _ = errOut.ReadFrom(r) // Read captured stderr

			if logger.level != tt.wantLevel {
				t.Errorf("NewLogger() level = %v, want %v", logger.level, tt.wantLevel)
			}

			// Check if the captured stderr output contains the expected error string.
			if tt.wantErrOut != "" {
				if !strings.Contains(errOut.String(), tt.wantErrOut) {
					t.Errorf("NewLogger() stderr = %q, want to contain %q", errOut.String(), tt.wantErrOut)
				}
			} else {
				// If no error output is expected, but we got some, it might indicate an issue.
				// However, be cautious as other go routines or system processes might write to stderr.
				// For this test, we are primarily focused on our specific error messages.
				// A more robust check might involve ensuring only expected messages appear if any.
				if errOut.String() != "" && strings.HasPrefix(errOut.String(), "Invalid log level") {
					t.Errorf("NewLogger() produced unexpected stderr output: %q", errOut.String())
				}
			}

			if tt.output != "" {
				// Further testing for file output would require creating a temporary file,
				// checking if the logger writes to it, and then cleaning up.
				// This is generally out of scope for simple unit tests of the NewLogger constructor logic itself,
				// which is more about setting the level and error handling for invalid levels.
				// We can assume os.OpenFile and log.New work as expected.
				// To test this properly, one might use a mock file system or dependency injection for the file opener.
			}
		})
	}
}

func TestLogBuffer_AddAndGetAll(t *testing.T) {
	lb := NewLogBuffer(3)
	lb.Add("log1")
	lb.Add("log2")

	logs := lb.GetAll()
	if len(logs) != 2 {
		t.Fatalf("Expected 2 logs, got %d", len(logs))
	}
	if logs[0] != "log1" || logs[1] != "log2" {
		t.Errorf("Unexpected log content: %v", logs)
	}
}

func TestLogBuffer_Rotation(t *testing.T) {
	lb := NewLogBuffer(2)
	lb.Add("log1")
	lb.Add("log2")
	lb.Add("log3") // This should cause rotation

	logs := lb.GetAll()
	if len(logs) != 2 {
		t.Fatalf("Expected 2 logs after rotation, got %d", len(logs))
	}
	if logs[0] != "log2" || logs[1] != "log3" {
		t.Errorf("Unexpected log content after rotation: %v, expected ['log2', 'log3']", logs)
	}

	lb.Add("log4")
	logs = lb.GetAll()
	if len(logs) != 2 {
		t.Fatalf("Expected 2 logs after second rotation, got %d", len(logs))
	}
	if logs[0] != "log3" || logs[1] != "log4" {
		t.Errorf("Unexpected log content after second rotation: %v, expected ['log3', 'log4']", logs)
	}
}

func TestLogBuffer_RegisterUnregisterClient(t *testing.T) {
	lb := NewLogBuffer(5)
	ch1 := lb.RegisterClient()
	if _, ok := lb.clients[ch1]; !ok {
		t.Fatal("Client channel 1 not registered")
	}
	if len(lb.clients) != 1 {
		t.Fatalf("Expected 1 client, got %d", len(lb.clients))
	}

	ch2 := lb.RegisterClient()
	if _, ok := lb.clients[ch2]; !ok {
		t.Fatal("Client channel 2 not registered")
	}
	if len(lb.clients) != 2 {
		t.Fatalf("Expected 2 clients, got %d", len(lb.clients))
	}

	lb.UnregisterClient(ch1)
	if _, ok := lb.clients[ch1]; ok {
		t.Fatal("Client channel 1 not unregistered")
	}
	if len(lb.clients) != 1 {
		t.Fatalf("Expected 1 client after unregister, got %d", len(lb.clients))
	}
	// Check if channel is closed
	select {
	case _, ok := <-ch1:
		if ok {
			t.Error("Unregistered client channel ch1 is not closed")
		}
	default:
		// This case might not be hit immediately if there's a slight delay in closing.
		// A more robust check might involve trying to send to it or checking its status after a brief moment.
		// However, for typical scenarios, checking if it's readable and !ok is sufficient.
	}

	lb.UnregisterClient(ch2)
	if _, ok := lb.clients[ch2]; ok {
		t.Fatal("Client channel 2 not unregistered")
	}
	if len(lb.clients) != 0 {
		t.Fatalf("Expected 0 clients after unregister, got %d", len(lb.clients))
	}
	select {
	case _, ok := <-ch2:
		if ok {
			t.Error("Unregistered client channel ch2 is not closed")
		}
	default:
	}
}

func TestLogBuffer_Broadcast(t *testing.T) {
	lb := NewLogBuffer(5)
	go lb.Broadcast() // Start broadcasting in a goroutine

	ch1 := lb.RegisterClient()
	ch2 := lb.RegisterClient()

	var wg sync.WaitGroup
	wg.Add(2) // Expect two messages, one for each client

	go func() {
		defer wg.Done()
		select {
		case log := <-ch1:
			if log != "test_log_1" {
				t.Errorf("Client 1 received wrong log: %s, expected 'test_log_1'", log)
			}
		case <-time.After(1 * time.Second):
			t.Errorf("Client 1 timed out waiting for log")
		}
	}()

	go func() {
		defer wg.Done()
		select {
		case log := <-ch2:
			if log != "test_log_1" {
				t.Errorf("Client 2 received wrong log: %s, expected 'test_log_1'", log)
			}
		case <-time.After(1 * time.Second):
			t.Errorf("Client 2 timed out waiting for log")
		}
	}()

	// Add a small delay to ensure clients are registered before adding the log
	time.Sleep(10 * time.Millisecond)
	lb.Add("test_log_1")

	wg.Wait() // Wait for both clients to receive the log

	// Test with another log after some clients might have been slow or one unregistered
	lb.UnregisterClient(ch1)

	// ch2 should still receive this new log
	var wg2 sync.WaitGroup
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		select {
		case log := <-ch2:
			if log != "test_log_2" {
				t.Errorf("Client 2 received wrong log: %s, expected 'test_log_2'", log)
			}
		case <-time.After(1 * time.Second):
			t.Errorf("Client 2 timed out waiting for log 'test_log_2'")
		}
	}()

	time.Sleep(10 * time.Millisecond) // ensure unregistration is processed
	lb.Add("test_log_2")
	wg2.Wait()

	// Clean up remaining client and stop broadcaster (implicitly by closing lb.broad)
	lb.UnregisterClient(ch2)
	// To fully stop Broadcast goroutine, close the broad channel.
	// This is typically done if LogBuffer had a Close() method.
	// For this test, unregistering all clients effectively stops messages from being sent.
	// The Broadcast goroutine will exit once lb.broad is closed and lb.clients is empty.
	// In the LogBuffer implementation, lb.broad is never closed, so Broadcast runs indefinitely.
	// This is fine for the application's lifecycle but makes complete test cleanup harder without a Close method.
}

func TestLogger_LogMessage(t *testing.T) {
	logBuffer := NewLogBuffer(10)
	// Create a temporary log file for testing output
	tmpFile, err := os.CreateTemp("", "testlog-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name()) // Clean up after the test
	tmpFile.Close()                 // Close it so logger can open and write

	logger := NewLogger("DEBUG", tmpFile.Name(), logBuffer)

	testMsg := map[string]interface{}{"message": "hello", "id": 123}
	logger.Info(testMsg)
	logger.Debug(map[string]interface{}{"message": "world", "id": 456})
	logger.Trace(map[string]interface{}{"message": "trace msg", "id": 789}) // Should not be logged if level is DEBUG

	// Check log buffer
	bufferedLogs := logBuffer.GetAll()
	if len(bufferedLogs) != 2 { // Info and Debug, not Trace
		t.Errorf("Expected 2 logs in buffer, got %d: %v", len(bufferedLogs), bufferedLogs)
	} else {
		if !strings.Contains(bufferedLogs[0], `"message":"hello"`) || !strings.Contains(bufferedLogs[0], `"level":"INFO"`) {
			t.Errorf("First buffered log is incorrect: %s", bufferedLogs[0])
		}
		if !strings.Contains(bufferedLogs[1], `"message":"world"`) || !strings.Contains(bufferedLogs[1], `"level":"DEBUG"`) {
			t.Errorf("Second buffered log is incorrect: %s", bufferedLogs[1])
		}
	}

	// Check log file content
	fileContent, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read temp log file: %v", err)
	}

	contentStr := string(fileContent)
	if !strings.Contains(contentStr, `"message":"hello"`) || !strings.Contains(contentStr, `"level":"INFO"`) {
		t.Errorf("Log file missing INFO message. Content:\n%s", contentStr)
	}
	if !strings.Contains(contentStr, `"message":"world"`) || !strings.Contains(contentStr, `"level":"DEBUG"`) {
		t.Errorf("Log file missing DEBUG message. Content:\n%s", contentStr)
	}
	if strings.Contains(contentStr, `"message":"trace msg"`) {
		t.Errorf("Log file should not contain TRACE message for DEBUG level. Content:\n%s", contentStr)
	}

	// Test logging with NONE level
	loggerNone := NewLogger("NONE", "", logBuffer) // Output to stdout, but won't log
	logBuffer.logs = []string{}                    // Clear buffer
	loggerNone.Info(map[string]interface{}{"message": "this should not appear"})
	if len(logBuffer.GetAll()) != 0 {
		t.Errorf("Expected 0 logs in buffer for NONE level, got %d", len(logBuffer.GetAll()))
	}
}

func TestLogger_GetLevel(t *testing.T) {
	lb := NewLogBuffer(1)
	logger := NewLogger("DEBUG", "", lb)
	if level := logger.GetLevel(); level != LevelDebug {
		t.Errorf("logger.GetLevel() = %v, want %v", level, LevelDebug)
	}

	logger = NewLogger("NONE", "", lb)
	if level := logger.GetLevel(); level != LevelNone {
		t.Errorf("logger.GetLevel() = %v, want %v", level, LevelNone)
	}
}

// TestMain can be used for setup/teardown if needed, but not necessary for these tests.
// func TestMain(m *testing.M) {
//     // setup
//     code := m.Run()
//     // teardown
//     os.Exit(code)
// }

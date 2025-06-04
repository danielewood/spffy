package logging

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// LogLevel defines the possible logging levels
type LogLevel int

const (
	LevelNone LogLevel = iota
	LevelInfo
	LevelDebug
	LevelTrace
)

// String returns the string representation of a LogLevel.
func (l LogLevel) String() string {
	switch l {
	case LevelNone:
		return "NONE"
	case LevelInfo:
		return "INFO"
	case LevelDebug:
		return "DEBUG"
	case LevelTrace:
		return "TRACE"
	default:
		return "UNKNOWN"
	}
}

// LogBuffer stores recent logs and broadcasts to clients
type LogBuffer struct {
	mu      sync.Mutex
	logs    []string
	maxSize int
	broad   chan string
	clients map[chan string]struct{}
}

func NewLogBuffer(maxSize int) *LogBuffer {
	return &LogBuffer{
		logs:    make([]string, 0, maxSize),
		maxSize: maxSize,
		broad:   make(chan string, 100),
		clients: make(map[chan string]struct{}),
	}
}

func (lb *LogBuffer) Add(log string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.logs = append(lb.logs, log)
	if len(lb.logs) > lb.maxSize {
		lb.logs = lb.logs[1:]
	}

	select {
	case lb.broad <- log:
	default:
	}
}

func (lb *LogBuffer) GetAll() []string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	return append([]string{}, lb.logs...)
}

func (lb *LogBuffer) RegisterClient() chan string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	ch := make(chan string, 100)
	lb.clients[ch] = struct{}{}
	return ch
}

func (lb *LogBuffer) UnregisterClient(ch chan string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	delete(lb.clients, ch)
	close(ch)
}

func (lb *LogBuffer) Broadcast() {
	for log := range lb.broad {
		lb.mu.Lock()
		for ch := range lb.clients {
			select {
			case ch <- log:
			default:
			}
		}
		lb.mu.Unlock()
	}
}

// Logger is a custom logger with leveled logging
type Logger struct {
	level  LogLevel
	writer *log.Logger
	buffer *LogBuffer
}

// NewLogger creates a new logger with the specified level and output
func NewLogger(levelStr string, output string, buffer *LogBuffer) *Logger {
	var level LogLevel
	switch strings.ToUpper(levelStr) {
	case "NONE":
		level = LevelNone
	case "INFO":
		level = LevelInfo
	case "DEBUG":
		level = LevelDebug
	case "TRACE":
		level = LevelTrace
	default:
		fmt.Fprintf(os.Stderr, "Invalid log level %s, defaulting to INFO\n", levelStr)
		level = LevelInfo
	}

	var writer *log.Logger
	if output != "" {
		f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file %s: %v\n", output, err)
			writer = log.New(os.Stdout, "", 0)
		} else {
			writer = log.New(f, "", 0)
		}
	} else {
		writer = log.New(os.Stdout, "", 0)
	}

	return &Logger{
		level:  level,
		writer: writer,
		buffer: buffer,
	}
}

// logMessage logs a message at the specified level with JSON formatting
func (l *Logger) logMessage(level LogLevel, msg map[string]interface{}) {
	if level > l.level {
		return
	}

	msg["level"] = levelToString(level)
	msg["timestamp"] = time.Now().Format(time.RFC3339)

	jsonData, err := json.Marshal(msg)
	if err != nil {
		return
	}

	logStr := string(jsonData)
	l.writer.Println(logStr)
	l.buffer.Add(logStr)
}

func levelToString(level LogLevel) string {
	switch level {
	case LevelNone:
		return "NONE"
	case LevelInfo:
		return "INFO"
	case LevelDebug:
		return "DEBUG"
	case LevelTrace:
		return "TRACE"
	default:
		return "UNKNOWN"
	}
}

// Info logs at INFO level
func (l *Logger) Info(msg map[string]interface{}) {
	l.logMessage(LevelInfo, msg)
}

// Debug logs at DEBUG level
func (l *Logger) Debug(msg map[string]interface{}) {
	l.logMessage(LevelDebug, msg)
}

// Trace logs at TRACE level
func (l *Logger) Trace(msg map[string]interface{}) {
	l.logMessage(LevelTrace, msg)
}

// GetLevel returns the current logging level of the logger
func (l *Logger) GetLevel() LogLevel {
	return l.level
}

// LoggerInterface defines the methods a logger should implement.
type LoggerInterface interface {
	Info(msg map[string]interface{})
	Debug(msg map[string]interface{})
	Trace(msg map[string]interface{})
	GetLevel() LogLevel
	Reconfigure(levelStr string, output string, buffer *LogBuffer) // Added for dynamic reconfiguration
}

// Reconfigure updates the logger's level and output destination.
// Note: This creates a new underlying *log.Logger.
// If the LogBuffer also needs to be changed, it's passed as a parameter.
func (l *Logger) Reconfigure(levelStr string, output string, buffer *LogBuffer) {
	// l.mu.Lock() // Logger currently doesn't have its own mutex, operations are on LogBuffer or are atomic writes to fields.
	// defer l.mu.Unlock() // Add mutex to Logger if concurrent Reconfigure calls are expected or if fields need protection.

	var newLevel LogLevel
	switch strings.ToUpper(levelStr) {
	case "NONE":
		newLevel = LevelNone
	case "INFO":
		newLevel = LevelInfo
	case "DEBUG":
		newLevel = LevelDebug
	case "TRACE":
		newLevel = LevelTrace
	default:
		fmt.Fprintf(os.Stderr, "Invalid log level %s during reconfigure, defaulting to INFO\n", levelStr)
		newLevel = LevelInfo
	}
	l.level = newLevel

	var newWriter *log.Logger
	if output != "" {
		// TODO: Consider closing the old file if l.writer was writing to a file.
		// This requires storing the *os.File handle in Logger.
		f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open new log file %s during reconfigure: %v. Using stdout.\n", output, err)
			newWriter = log.New(os.Stdout, "", 0)
		} else {
			newWriter = log.New(f, "", 0)
		}
	} else {
		// TODO: Consider closing old file if switching from file to stdout.
		newWriter = log.New(os.Stdout, "", 0)
	}
	l.writer = newWriter

	if buffer != nil { // Allow updating the log buffer as well
		l.buffer = buffer
	}
}

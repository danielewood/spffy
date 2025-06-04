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
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

// String returns the string representation of a LogLevel.
func (l LogLevel) String() string {
	switch l {
	case LevelNone:
		return "NONE"
	case LevelError:
		return "ERROR"
	case LevelWarn:
		return "WARN"
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
	case "ERROR":
		level = LevelError
	case "WARN":
		level = LevelWarn
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
	// Log if the message level is less than or equal to the logger's level
	// Hierarchy: ERROR > WARN > INFO > DEBUG > TRACE
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
	case LevelError:
		return "ERROR"
	case LevelWarn:
		return "WARN"
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

// Error logs at ERROR level
func (l *Logger) Error(msg map[string]interface{}) {
	l.logMessage(LevelError, msg)
}

// Warn logs at WARN level
func (l *Logger) Warn(msg map[string]interface{}) {
	l.logMessage(LevelWarn, msg)
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
	Error(msg map[string]interface{})
	Warn(msg map[string]interface{})
	GetLevel() LogLevel
	Reconfigure(levelStr string, output string, buffer *LogBuffer)
}

// Reconfigure updates the logger's level and output destination.
func (l *Logger) Reconfigure(levelStr string, output string, buffer *LogBuffer) {
	var newLevel LogLevel
	switch strings.ToUpper(levelStr) {
	case "NONE":
		newLevel = LevelNone
	case "ERROR":
		newLevel = LevelError
	case "WARN":
		newLevel = LevelWarn
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
		f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open new log file %s during reconfigure: %v. Using stdout.\n", output, err)
			newWriter = log.New(os.Stdout, "", 0)
		} else {
			newWriter = log.New(f, "", 0)
		}
	} else {
		newWriter = log.New(os.Stdout, "", 0)
	}
	l.writer = newWriter

	if buffer != nil {
		l.buffer = buffer
	}
}

// Package log is the process logger. The default format is text.
// log.format set to json switches the process to JSON.
package log

import (
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	mu  sync.RWMutex
	std = slog.New(slog.NewTextHandler(os.Stderr, nil))
)

// Setup selects the process log format. An empty format stays text.
func Setup(format string) {
	var handler slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	} else {
		handler = slog.NewTextHandler(os.Stderr, nil)
	}
	mu.Lock()
	std = slog.New(handler)
	mu.Unlock()
}

func logger() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return std
}

// Info writes an informational record.
func Info(msg string, args ...any) {
	logger().Info(msg, args...)
}

// Warn writes a warning.
func Warn(msg string, args ...any) {
	logger().Warn(msg, args...)
}

// Error writes an error record.
func Error(msg string, args ...any) {
	logger().Error(msg, args...)
}

// Fatal writes an error record and exits the process.
func Fatal(msg string, args ...any) {
	logger().Error(msg, args...)
	os.Exit(1)
}

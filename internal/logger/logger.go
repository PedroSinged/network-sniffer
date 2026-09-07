// Package logger writes captured events to a persistent log plus a
// per-session log file. Writes are buffered and flushed on Close.
package logger

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/PedroSinged/network-sniffer/internal/event"
)

// Logger fans each event out to the main and session log files.
type Logger struct {
	mu      sync.Mutex
	writers []*bufio.Writer
	files   []*os.File
}

// New creates (or appends to) logs/sniffer.log and creates a timestamped
// session log inside dir.
func New(dir string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}

	l := &Logger{}
	open := func(name string) error {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			l.Close()
			return fmt.Errorf("open %s: %w", name, err)
		}
		l.files = append(l.files, f)
		l.writers = append(l.writers, bufio.NewWriter(f))
		return nil
	}

	if err := open("sniffer.log"); err != nil {
		return nil, err
	}
	session := fmt.Sprintf("sniffer_%s.log", time.Now().Format("2006-01-02_15-04-05"))
	if err := open(session); err != nil {
		return nil, err
	}
	return l, nil
}

// Log appends one timestamped line per event to every log file.
func (l *Logger) Log(e event.Event) {
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), e.String())
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range l.writers {
		_, _ = w.WriteString(line)
	}
}

// Flush pushes buffered data to disk.
func (l *Logger) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range l.writers {
		_ = w.Flush()
	}
}

// Close flushes and closes every log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range l.writers {
		_ = w.Flush()
	}
	var firstErr error
	for _, f := range l.files {
		if err := f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	l.writers, l.files = nil, nil
	return firstErr
}

package logx

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Logger struct {
	out io.Writer
	mu  sync.Mutex
}

func New(enableFile bool, logDir string) (*Logger, error) {
	writers := []io.Writer{os.Stdout}
	if enableFile {
		if err := os.MkdirAll(logDir, 0o750); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(filepath.Join(logDir, "domnexdomain.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, err
		}
		writers = append(writers, f)
	}
	return &Logger{out: io.MultiWriter(writers...)}, nil
}

func (l *Logger) Write(level, msg string, fields map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	payload := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"level": level,
		"msg":   msg,
	}
	for k, v := range fields {
		payload[k] = v
	}
	b, _ := json.Marshal(payload)
	_, _ = l.out.Write(append(b, '\n'))
}

func (l *Logger) Debug(msg string, fields map[string]any) { l.Write("debug", msg, fields) }
func (l *Logger) Info(msg string, fields map[string]any)  { l.Write("info", msg, fields) }
func (l *Logger) Warn(msg string, fields map[string]any)  { l.Write("warn", msg, fields) }
func (l *Logger) Error(msg string, fields map[string]any) { l.Write("error", msg, fields) }

func StdLogger(l *Logger) *log.Logger {
	return log.New(writerFunc(func(p []byte) (int, error) {
		l.Info("stdlib", map[string]any{"line": string(p)})
		return len(p), nil
	}), "", 0)
}

type writerFunc func(p []byte) (int, error)

func (w writerFunc) Write(p []byte) (int, error) { return w(p) }

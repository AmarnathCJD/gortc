// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
)

// Logger is gortc's thin leveled logger, wrapping *slog.Logger.
type Logger struct {
	sl *slog.Logger
}

type Option func(*config)

type config struct {
	level   slog.Level
	out     io.Writer
	handler slog.Handler
}

func WithLevel(l slog.Level) Option {
	return func(c *config) { c.level = l }
}

func WithOutput(w io.Writer) Option {
	return func(c *config) { c.out = w }
}

// WithHandler supplies a custom slog.Handler, overriding level/output.
func WithHandler(h slog.Handler) Option {
	return func(c *config) { c.handler = h }
}

// New builds a Logger from options. With no options it logs WARN+ to stderr.
func New(opts ...Option) *Logger {
	c := &config{level: slog.LevelWarn, out: os.Stderr}
	for _, o := range opts {
		o(c)
	}
	h := c.handler
	if h == nil {
		h = slog.NewTextHandler(c.out, &slog.HandlerOptions{Level: c.level})
	}

	return &Logger{sl: slog.New(h)}
}

// From wraps an existing *slog.Logger; a nil sl yields a disabled logger.
func From(sl *slog.Logger) *Logger {
	if sl == nil {
		return Disabled()
	}

	return &Logger{sl: sl}
}

// Disabled returns a logger that discards everything.
func Disabled() *Logger {
	h := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1})

	return &Logger{sl: slog.New(h)}
}

// With returns a child logger that attaches the given attrs to every record.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{sl: l.sl.With(args...)}
}

func (l *Logger) Debugf(format string, args ...any) { l.logf(slog.LevelDebug, format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.logf(slog.LevelInfo, format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.logf(slog.LevelWarn, format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.logf(slog.LevelError, format, args...) }

func (l *Logger) logf(level slog.Level, format string, args ...any) {
	if l == nil || l.sl == nil || !l.sl.Enabled(context.Background(), level) {
		return
	}
	l.sl.Log(context.Background(), level, fmt.Sprintf(format, args...))
}

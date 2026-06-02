// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package webrtc

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

type LogLevel int32

func (ll *LogLevel) Get() LogLevel {
	return LogLevel(atomic.LoadInt32((*int32)(ll)))
}

const (
	LogLevelDisabled LogLevel = iota
	LogLevelError
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

type LeveledLogger interface {
	Trace(msg string)
	Tracef(format string, args ...any)
	Debug(msg string)
	Debugf(format string, args ...any)
	Info(msg string)
	Infof(format string, args ...any)
	Warn(msg string)
	Warnf(format string, args ...any)
	Error(msg string)
	Errorf(format string, args ...any)
}

type LoggerFactory interface {
	NewLogger(scope string) LeveledLogger
}

type loggerWriter struct {
	sync.RWMutex
	output io.Writer
}

func (lw *loggerWriter) Write(data []byte) (int, error) {
	lw.RLock()
	defer lw.RUnlock()
	return lw.output.Write(data)
}

type DefaultLeveledLogger struct {
	level  LogLevel
	writer *loggerWriter
	trace  *log.Logger
	debug  *log.Logger
	info   *log.Logger
	warn   *log.Logger
	err    *log.Logger
}

func (ll *DefaultLeveledLogger) WithTraceLogger(log *log.Logger) *DefaultLeveledLogger {
	ll.trace = log
	return ll
}

func (ll *DefaultLeveledLogger) WithDebugLogger(log *log.Logger) *DefaultLeveledLogger {
	ll.debug = log
	return ll
}

func (ll *DefaultLeveledLogger) WithInfoLogger(log *log.Logger) *DefaultLeveledLogger {
	ll.info = log
	return ll
}

func (ll *DefaultLeveledLogger) WithWarnLogger(log *log.Logger) *DefaultLeveledLogger {
	ll.warn = log
	return ll
}

func (ll *DefaultLeveledLogger) WithErrorLogger(log *log.Logger) *DefaultLeveledLogger {
	ll.err = log
	return ll
}

func (ll *DefaultLeveledLogger) logf(logger *log.Logger, level LogLevel, format string, args ...any) {
	if ll.level.Get() < level {
		return
	}
	callDepth := 3
	msg := fmt.Sprintf(format, args...)
	if err := logger.Output(callDepth, msg); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to log: %s", err)
	}
}

func (ll *DefaultLeveledLogger) Trace(msg string)          { ll.logf(ll.trace, LogLevelTrace, "%s", msg) }
func (ll *DefaultLeveledLogger) Tracef(f string, a ...any) { ll.logf(ll.trace, LogLevelTrace, f, a...) }
func (ll *DefaultLeveledLogger) Debug(msg string)          { ll.logf(ll.debug, LogLevelDebug, "%s", msg) }
func (ll *DefaultLeveledLogger) Debugf(f string, a ...any) { ll.logf(ll.debug, LogLevelDebug, f, a...) }
func (ll *DefaultLeveledLogger) Info(msg string)           { ll.logf(ll.info, LogLevelInfo, "%s", msg) }
func (ll *DefaultLeveledLogger) Infof(f string, a ...any)  { ll.logf(ll.info, LogLevelInfo, f, a...) }
func (ll *DefaultLeveledLogger) Warn(msg string)           { ll.logf(ll.warn, LogLevelWarn, "%s", msg) }
func (ll *DefaultLeveledLogger) Warnf(f string, a ...any)  { ll.logf(ll.warn, LogLevelWarn, f, a...) }
func (ll *DefaultLeveledLogger) Error(msg string)          { ll.logf(ll.err, LogLevelError, "%s", msg) }
func (ll *DefaultLeveledLogger) Errorf(f string, a ...any) { ll.logf(ll.err, LogLevelError, f, a...) }

func NewDefaultLeveledLoggerForScope(scope string, level LogLevel, writer io.Writer) *DefaultLeveledLogger {
	if writer == nil {
		writer = os.Stderr
	}
	logger := &DefaultLeveledLogger{
		writer: &loggerWriter{output: writer},
		level:  level,
	}
	return logger.
		WithTraceLogger(log.New(logger.writer, fmt.Sprintf("%s TRACE: ", scope), log.Lmicroseconds|log.Lshortfile)).
		WithDebugLogger(log.New(logger.writer, fmt.Sprintf("%s DEBUG: ", scope), log.Lmicroseconds|log.Lshortfile)).
		WithInfoLogger(log.New(logger.writer, fmt.Sprintf("%s INFO: ", scope), log.LstdFlags)).
		WithWarnLogger(log.New(logger.writer, fmt.Sprintf("%s WARNING: ", scope), log.LstdFlags)).
		WithErrorLogger(log.New(logger.writer, fmt.Sprintf("%s ERROR: ", scope), log.LstdFlags))
}

type DefaultLoggerFactory struct {
	Writer          io.Writer
	DefaultLogLevel LogLevel
	ScopeLevels     map[string]LogLevel
}

func NewDefaultLoggerFactory() *DefaultLoggerFactory {
	factory := DefaultLoggerFactory{}
	factory.DefaultLogLevel = LogLevelError
	factory.ScopeLevels = make(map[string]LogLevel)
	factory.Writer = os.Stderr

	logLevels := map[string]LogLevel{
		"DISABLE": LogLevelDisabled,
		"ERROR":   LogLevelError,
		"WARN":    LogLevelWarn,
		"INFO":    LogLevelInfo,
		"DEBUG":   LogLevelDebug,
		"TRACE":   LogLevelTrace,
	}

	for name, level := range logLevels {
		env := os.Getenv(fmt.Sprintf("LOG_%s", name))
		if env == "" {
			continue
		}
		if strings.ToLower(env) == "all" {
			if factory.DefaultLogLevel < level {
				factory.DefaultLogLevel = level
			}
			continue
		}
		scopes := strings.Split(strings.ToLower(env), ",")
		for _, scope := range scopes {
			factory.ScopeLevels[scope] = level
		}
	}
	return &factory
}

func (f *DefaultLoggerFactory) NewLogger(scope string) LeveledLogger {
	logLevel := f.DefaultLogLevel
	if f.ScopeLevels != nil {
		if scopeLevel, found := f.ScopeLevels[scope]; found {
			logLevel = scopeLevel
		}
	}
	return NewDefaultLeveledLoggerForScope(scope, logLevel, f.Writer)
}

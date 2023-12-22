package observability

import (
	"fmt"
	chiMiddleware "github.com/go-chi/chi/middleware"
	"github.com/sirupsen/logrus"
	"github.com/travel2x/gotrust/internal/conf"
	"github.com/travel2x/gotrust/internal/utilities"
	"net/http"
	"time"
)

type StructuredLogger struct {
	Logger *logrus.Logger
	Config *conf.GlobalConfiguration
}

func NewStructuredLogger(logger *logrus.Logger, config *conf.GlobalConfiguration) func(next http.Handler) http.Handler {
	return chiMiddleware.RequestLogger(&StructuredLogger{logger, config})
}

func (l *StructuredLogger) NewLogEntry(r *http.Request) chiMiddleware.LogEntry {
	referrer := utilities.GetReferrer(r, l.Config)
	entry := &StructuredLoggerEntry{Logger: logrus.NewEntry(l.Logger)}
	logFields := logrus.Fields{
		"component":   "api",
		"method":      r.Method,
		"path":        r.URL.Path,
		"remote_addr": utilities.GetIPAddress(r),
		"referer":     referrer,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}

	if reqID := r.Context().Value("request_id"); reqID != nil {
		logFields["request_id"] = reqID.(string)
	}
	entry.Logger = entry.Logger.WithFields(logFields)
	entry.Logger.Infoln("request started")

	return entry
}

type StructuredLoggerEntry struct {
	Logger logrus.FieldLogger
}

func (l *StructuredLoggerEntry) Write(status, bytes int, header http.Header, elapsed time.Duration, extra interface{}) {
	l.Logger = l.Logger.WithFields(logrus.Fields{
		"status":   status,
		"duration": elapsed.Nanoseconds(),
	})

	l.Logger.Info("request completed")
}

func (l *StructuredLoggerEntry) Panic(v interface{}, stack []byte) {
	l.Logger.WithFields(logrus.Fields{
		"stack": string(stack),
		"panic": fmt.Sprintf("%+v", v),
	}).Panic("unhandled request panic")
}

func GetLogEntry(r *http.Request) logrus.FieldLogger {
	entry, _ := chiMiddleware.GetLogEntry(r).(*StructuredLoggerEntry)
	if entry == nil {
		return logrus.NewEntry(logrus.StandardLogger())
	}
	return entry.Logger
}

func LogEntrySetField(r *http.Request, key string, value interface{}) logrus.FieldLogger {
	if entry, ok := r.Context().Value(chiMiddleware.LogEntryCtxKey).(*StructuredLoggerEntry); ok {
		entry.Logger = entry.Logger.WithField(key, value)
		return entry.Logger
	}
	return nil
}

func LogEntrySetFields(r *http.Request, fields logrus.Fields) logrus.FieldLogger {
	if entry, ok := r.Context().Value(chiMiddleware.LogEntryCtxKey).(*StructuredLoggerEntry); ok {
		entry.Logger = entry.Logger.WithFields(fields)
		return entry.Logger
	}
	return nil
}

package logging

import (
    "log"
    "net/http"
    "time"
)

type LoggingMiddleware struct {
    logger *log.Logger
}

func NewLoggingMiddleware(logger *log.Logger) *LoggingMiddleware {
    if logger == nil {
        logger = log.Default()
    }
    return &LoggingMiddleware{
        logger: logger,
    }
}

func (m *LoggingMiddleware) Logger(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        wrapped := NewResponseWriter(w)

        // Process request
        next.ServeHTTP(wrapped, r)

        // Log request details
        m.logger.Printf(
            "method=%s path=%s status=%d duration=%s bytes=%d ip=%s",
            r.Method,
            r.URL.Path,
            wrapped.Status(),
            time.Since(start),
            wrapped.BytesWritten(),
            r.RemoteAddr,
        )
    }
}
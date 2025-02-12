package logging

import "net/http"

// ResponseWriter wraps http.ResponseWriter to capture the status code
type ResponseWriter struct {
    http.ResponseWriter
    status      int
    wroteHeader bool
    written     int64
}

func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
    return &ResponseWriter{
        ResponseWriter: w,
        status:        http.StatusOK,
    }
}

func (rw *ResponseWriter) Status() int {
    return rw.status
}

func (rw *ResponseWriter) BytesWritten() int64 {
    return rw.written
}

func (rw *ResponseWriter) WriteHeader(code int) {
    if rw.wroteHeader {
        return
    }
    rw.status = code
    rw.ResponseWriter.WriteHeader(code)
    rw.wroteHeader = true
}

func (rw *ResponseWriter) Write(b []byte) (int, error) {
    if !rw.wroteHeader {
        rw.WriteHeader(http.StatusOK)
    }
    n, err := rw.ResponseWriter.Write(b)
    rw.written += int64(n)
    return n, err
}
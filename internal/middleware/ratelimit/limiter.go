package ratelimit

import (
    "fmt"
    "net/http"
    "sync"
    "time"
)

type Limiter struct {
    requests map[string][]time.Time
    mu       sync.Mutex
    max      int           // maximum requests
    duration time.Duration // time window
}

func NewLimiter(max int, duration time.Duration) *Limiter {
    return &Limiter{
        requests: make(map[string][]time.Time),
        max:      max,
        duration: duration,
    }
}

func (l *Limiter) cleanup(now time.Time) {
    for ip, times := range l.requests {
        var valid []time.Time
        for _, t := range times {
            if now.Sub(t) <= l.duration {
                valid = append(valid, t)
            }
        }
        if len(valid) == 0 {
            delete(l.requests, ip)
        } else {
            l.requests[ip] = valid
        }
    }
}

func (l *Limiter) isAllowed(ip string) bool {
    l.mu.Lock()
    defer l.mu.Unlock()

    now := time.Now()
    l.cleanup(now)

    times := l.requests[ip]
    if len(times) < l.max {
        l.requests[ip] = append(times, now)
        return true
    }

    fmt.Printf("Rate limit exceeded for IP: %s. Count: %d, Limit: %d\n",
        ip, len(times), l.max)
    return false
}

// RateLimit returns a middleware function that matches the Middleware type
func (l *Limiter) RateLimit(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        ip := r.Header.Get("X-Real-IP")
        if ip == "" {
            ip = r.Header.Get("X-Forwarded-For")
        }
        if ip == "" {
            ip = r.RemoteAddr
        }

        if !l.isAllowed(ip) {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusTooManyRequests)
            w.Write([]byte(`{"error": "Rate limit exceeded. Please try again later."}`))
            return
        }

        next.ServeHTTP(w, r)
    }
}
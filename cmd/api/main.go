package main

import (
    "encoding/json"
    "log"
    "net/http"
    "os"
    "time"

    "go-sandbox/internal/middleware"
    "go-sandbox/internal/middleware/auth"
    "go-sandbox/internal/middleware/logging"
)

type Response struct {
    Message string `json:"message"`
    Status  string `json:"status"`
}

func main() {
    // Initialize services
    logger := log.New(os.Stdout, "", log.LstdFlags)
    jwtService := auth.NewJWTService("your-secret-key", 24*time.Hour)

    // Initialize middlewares
    authMiddleware := auth.NewAuthMiddleware(jwtService)
    loggingMiddleware := logging.NewLoggingMiddleware(logger)

    // Routes
    http.HandleFunc("/", middleware.Chain(
        handleHome,
        loggingMiddleware.Logger,
    ))

    http.HandleFunc("/health", middleware.Chain(
        handleHealth,
    ))

    http.HandleFunc("/protected", middleware.Chain(
        handleProtected,
        loggingMiddleware.Logger,
        authMiddleware.Authenticate,
        authMiddleware.RequireRole("admin"),
    ))

    // Start server
    logger.Println("Server starting on :8090")
    if err := http.ListenAndServe(":8090", nil); err != nil {
        logger.Fatal(err)
    }
}

func handleHome( w http.ResponseWriter, r *http.Request) {
    response := Response{
        Message: "Welcome to Go Sandbox",
        Status: "success",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
    response := Response{
        Message: "Server is running",
        Status: "up",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
    // Handler implementation
}
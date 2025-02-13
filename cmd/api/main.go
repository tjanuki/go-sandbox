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

type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type LoginResponse struct {
    Token string `json:"token"`
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
        loggingMiddleware.Logger,
    ))

    http.HandleFunc("/login", middleware.Chain(
        makeLoginHandler(jwtService),
        loggingMiddleware.Logger,
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

func handleHome(w http.ResponseWriter, r *http.Request) {
    response := Response{
        Message: "Welcome to Go Sandbox",
        Status:  "success",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
    response := Response{
        Message: "Server is running",
        Status:  "up",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func makeLoginHandler(jwtService *auth.JWTService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }

        var loginReq LoginRequest
        if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
            http.Error(w, "Invalid request body", http.StatusBadRequest)
            return
        }

        // In a real application, validate credentials against a database
        if loginReq.Username == "admin" && loginReq.Password == "password" {
            // Generate token with role
            token, err := jwtService.GenerateToken(loginReq.Username, "admin")
            if err != nil {
                http.Error(w, "Error generating token", http.StatusInternalServerError)
                return
            }

            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(LoginResponse{Token: token})
            return
        }

        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
    }
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value(auth.UserIDKey).(string)
    response := Response{
        Message: "Protected endpoint accessed by user: " + userID,
        Status:  "success",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
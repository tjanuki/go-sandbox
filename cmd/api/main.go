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

type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
}

func main() {
    // Initialize services
    logger := log.New(os.Stdout, "", log.LstdFlags)
    jwtService := auth.NewJWTService(
        "your-secret-key",
        15*time.Minute,  // Access token expires in 15 minutes
        24*7*time.Hour,  // Refresh token expires in 7 days
    )

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

    http.HandleFunc("/refresh", middleware.Chain(
        makeRefreshHandler(jwtService),
        loggingMiddleware.Logger,
    ))

    // Note the order of middleware: first log, then authenticate, then check role
    http.HandleFunc("/protected", middleware.Chain(
        handleProtected,
        authMiddleware.RequireRole("admin"),
        authMiddleware.Authenticate,
        loggingMiddleware.Logger,
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
            // Generate access token
             accessToken, err := jwtService.GenerateAccessToken(loginReq.Username, "admin")
            if err != nil {
                http.Error(w, "Error generating access token", http.StatusInternalServerError)
                return
            }

            // Generate refresh token
            refreshToken, err := jwtService.GenerateRefreshToken(loginReq.Username, "admin")
            if err != nil {
                http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
                return
            }

            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(TokenResponse{
                AccessToken:  accessToken,
                RefreshToken: refreshToken,
            })
            return
        }

        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
    }
}

func makeRefreshHandler(jwtService *auth.JWTService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }

        refreshToken := r.Header.Get("X-Refresh-Token")
        if refreshToken == "" {
            http.Error(w, "Refresh token required", http.StatusBadRequest)
            return
        }

        // Validate refresh token
        claims, err := jwtService.ValidateToken(refreshToken)
        if err != nil {
            http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
            return
        }

        // Verify it's a refresh token
        if claims.TokenType != auth.RefreshToken {
            http.Error(w, "Invalid token type", http.StatusUnauthorized)
            return
        }

        // Generate new access token
        accessToken, err := jwtService.GenerateAccessToken(claims.UserID, claims.Role)
        if err != nil {
            http.Error(w, "Error generating access token", http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(TokenResponse{
            AccessToken:  accessToken,
            RefreshToken: refreshToken, // Return the same refresh token
        })
    }
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value(auth.UserIDKey).(string)
    role := r.Context().Value(auth.RoleKey).(string)  // Get the role from context

    response := Response{
        Message: "Protected endpoint accessed by user: " + userID + " with role: " + role,
        Status:  "success",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
package auth

import (
    "context"
    "fmt"
    "net/http"
    "strings"
)

type AuthMiddleware struct {
    jwtService *JWTService
}

func NewAuthMiddleware(jwtService *JWTService) *AuthMiddleware {
    return &AuthMiddleware{
        jwtService: jwtService,
    }
}

func (m *AuthMiddleware) Authenticate(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header required", http.StatusUnauthorized)
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        claims, err := m.jwtService.ValidateToken(tokenString)
        if err != nil {
            switch err {
            case ErrExpiredToken:
                http.Error(w, "Token has expired", http.StatusUnauthorized)
            default:
                http.Error(w, "Invalid token", http.StatusUnauthorized)
            }
            return
        }

        // Add claims to context
        ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
        ctx = context.WithValue(ctx, RoleKey, claims.Role)  // Make sure Role is added to context

        // Debug logging
        fmt.Printf("User ID from token: %s\n", claims.UserID)
        fmt.Printf("Role from token: %s\n", claims.Role)

        next.ServeHTTP(w, r.WithContext(ctx))
    }
}

func (m *AuthMiddleware) RequireRole(role string) func(http.HandlerFunc) http.HandlerFunc {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
            userRole, ok := r.Context().Value(RoleKey).(string)
            if !ok {
                http.Error(w, "Role not found in context", http.StatusInternalServerError)
                return
            }

            // Debug logging
            fmt.Printf("Required role: %s, User role: %s\n", role, userRole)

            if userRole != role {
                http.Error(w, "Insufficient permissions", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        }
    }
}
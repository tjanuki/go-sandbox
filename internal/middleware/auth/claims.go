package auth

import "github.com/golang-jwt/jwt/v5"

// Claims represents the JWT claims structure
type Claims struct {
    UserID string `json:"user_id"`
    Role   string `json:"role"`
    jwt.RegisteredClaims
}

// UserContext is the key type for context values
type UserContext string

// Context keys
const (
    UserIDKey UserContext = "user_id"
    RoleKey   UserContext = "role"
)
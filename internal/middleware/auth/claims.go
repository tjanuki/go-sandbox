package auth

import "github.com/golang-jwt/jwt/v5"

// TokenType represents the type of JWT token
type TokenType string

const (
    AccessToken  TokenType = "access"
    RefreshToken TokenType = "refresh"
)

// Claims represents the JWT claims structure
type Claims struct {
    UserID    string    `json:"user_id"`
    Role      string    `json:"role"`
    TokenType TokenType `json:"token_type"`
    jwt.RegisteredClaims
}

// UserContext is the key type for context values
type UserContext string

// Context keys
const (
    UserIDKey UserContext = "user_id"
    RoleKey   UserContext = "role"
)
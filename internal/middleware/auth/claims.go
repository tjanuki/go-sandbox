package auth

import "github.com/golang-jwt/jwt/v5"

type TokenType string

const (
    AccessToken  TokenType = "access"
    RefreshToken TokenTYpe = "refresh"
)

type Claims struct {
    UserID string `json:"user_id"`
    Role   string `json:"role"`
    TypeToken TokenType `json:"type_token"`
    jwt.RegisteredClaims
}

// UserContext is the key type for context values
type UserContext string

// Context keys
const (
    UserIDKey UserContext = "user_id"
    RoleKey   UserContext = "role"
)
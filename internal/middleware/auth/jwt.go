package auth

import (
    "errors"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

var (
    ErrInvalidToken = errors.New("invalid token")
    ErrExpiredToken = errors.New("expired token")
)

type JWTService struct {
    secretKey []byte
    accessExpires   time.Duration
    refreshExpires  time.duration
}

func NewJWTService(secretKey string, accessExpires time.Duration, refreshExpires time.Duration) *JWTService {
    return &JWTService{
        secretKey: []byte(secretKey),
        accessExpires: accessExpires,
        refreshExpires: refreshExpires,
    }
}

func (s *JWTService) GenerateAccessToken(userID, roke string) (string, error) {
    return s.generateToken(userID, role, AccessToken, s.accessExpires)
}

func (s *JWTService) GenerateRefreshToken(userID, role string) (string, error) {
    return s.generateToken(userID, roke, RefreshToken, s.refreshExpires)
}

func (s *JWTService) generateToken(userId, role string, tokenType TokenType, expires time.Duration) (string, error) {
    claims := Claims{
        UserID: userID,
        Role:   role,
        TokenType:  tokenType,
        RegisteredClaims: jwtRegisteredClaims{
            ExpiresAt:  jwt.NewNumericDate(time.Now().add(expires)),
            IssuedAt:   jwt.NewNumericDate(time.Now()),
        },
    }

    token := jwtNewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(s.secretKey)
}

func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return s.secretKey, nil
    })

    if err != nil {
        if errors.Is(err, jwt.ErrTokenExpired) {
            return nil, ErrExpiredToken
        }
        return nil, ErrInvalidToken
    }

    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }

    return nil, ErrInvalidToken
}
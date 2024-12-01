package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------------------------
// Комментарии для объяснения своих действий, а также лучшего понимания кода | t.me/fakelag
// -----------------------------------------------------------------------------------------------

// Структура данных для возврата токенов, AccessToken и RefreshToken
type AccessTokenRefreshToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Структура данных для хранения RefreshToken в базе данных
type RefreshTokenData struct {
	ID            uuid.UUID `json:"id"`
	UserID        uuid.UUID `json:"user_id"`
	TokenHash     string    `json:"token_hash"`
	ClientIP      string    `json:"client_ip"`
	AccessTokenID string    `json:"access_token_id"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Used          bool      `json:"used"`
}

// Структура данных для хранения Claims в JWT
type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	TokenID  uuid.UUID `json:"token_id"`
	ClientIP string    `json:"client_ip"`
	jwt.RegisteredClaims
}

package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"juniortest/internal/models"
	"juniortest/internal/repository"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AuthService struct {
	tokenRepository repository.TokenRepository
	jwtSecret       []byte
}

func NewAuthService(tokenRepository repository.TokenRepository, jwtSecret []byte) *AuthService {
	return &AuthService{
		tokenRepository: tokenRepository,
		jwtSecret:       jwtSecret,
	}
}

// generateAccessToken создает новый access token
func (as *AuthService) generateAccessToken(tokenID uuid.UUID, userID uuid.UUID, clientIP string) (string, error) {
	claims := jwt.MapClaims{
		"token_id":  tokenID.String(),
		"user_id":   userID.String(),
		"client_ip": clientIP,
		"exp":       time.Now().Add(time.Minute * 15).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(as.jwtSecret)
}

// generateRefreshToken создает новый refresh token
func (as *AuthService) generateRefreshToken(tokenID uuid.UUID, userID uuid.UUID, clientIP string) (string, error) {
	fmt.Printf("Processing GetTokens for user_id: %s, clientIP: %s\n", userID, clientIP)

	// Генерация случайного токена
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// Кодирование в base64 самого токена
	return base64.StdEncoding.EncodeToString(b), nil
}

// generateTokenHash создает bcrypt хэш для refresh token
func generateTokenHash(token string) (string, error) {
	// Генерация хэша через либу bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// GetTokens обращается к CreateTokenPair для создания пары токенов
func (as *AuthService) GetTokens(userID string, clientIP string) (*models.AccessTokenRefreshToken, error) {
	fmt.Printf("GetTokens called with userID: %s, clientIP: %s\n", userID, clientIP)

	// Преобразование userID из строки в UUID
	uid, err := uuid.Parse(userID)
	if err != nil {
		fmt.Printf("Error parsing UUID: %v\n", err)
		return nil, fmt.Errorf("invalid user_id format: %v", err)
	}

	// Создание пары токенов
	tokens, err := as.CreateTokenPair(context.Background(), uid, clientIP)
	if err != nil {
		fmt.Printf("Error creating token pair: %v\n", err)
		return nil, err
	}

	return tokens, nil
}

// CreateTokenPair создает пару токенов
func (as *AuthService) CreateTokenPair(ctx context.Context, userID uuid.UUID, clientIP string) (*models.AccessTokenRefreshToken, error) {
	fmt.Printf("CreateTokenPair started for userID: %s, clientIP: %s\n", userID, clientIP)

	accessTokenID := uuid.New()  // Генерация ID для AccessToken
	refreshTokenID := uuid.New() // Генерация ID для RefreshToken

	// Генерация AccessToken
	accessToken, err := as.generateAccessToken(accessTokenID, userID, clientIP)
	if err != nil {
		fmt.Printf("Error generating access token: %v\n", err)
		return nil, fmt.Errorf("failed to generate access token: %v", err)
	}
	fmt.Printf("Access token generated successfully\n")

	// Генерация RefreshToken
	refreshToken, err := as.generateRefreshToken(refreshTokenID, userID, clientIP)
	if err != nil {
		fmt.Printf("Error generating refresh token: %v\n", err)
		return nil, fmt.Errorf("failed to generate refresh token: %v", err)
	}
	fmt.Printf("Refresh token generated successfully\n")

	// Создание хэша
	tokenHash, err := generateTokenHash(refreshToken)
	if err != nil {
		fmt.Printf("Error generating token hash: %v\n", err)
		return nil, fmt.Errorf("failed to hash refresh token: %v", err)
	}
	fmt.Printf("Token hash generated successfully\n")

	refreshTokenData := &models.RefreshTokenData{
		ID:            refreshTokenID,
		UserID:        userID,
		TokenHash:     tokenHash,
		ClientIP:      clientIP,
		AccessTokenID: accessTokenID.String(),
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour * 24),
		Used:          false,
	}

	fmt.Printf("Attempting to save refresh token to DB with ID: %s\n", refreshTokenData.ID)

	// Сохранение в БД с подробным логированием ошибки
	if err := as.tokenRepository.SaveRefreshToken(ctx, refreshTokenData); err != nil {
		fmt.Printf("Detailed DB error: %+v\n", err)
		return nil, fmt.Errorf("failed to save refresh token to database: %v", err)
	}

	fmt.Printf("Successfully saved refresh token to DB\n")

	return &models.AccessTokenRefreshToken{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// RefreshToken обновляет пару токенов, используя refresh token
func (as *AuthService) RefreshToken(refreshToken string, clientIP string) (*models.AccessTokenRefreshToken, error) {
	// Получение данных из БД
	tokenData, err := as.tokenRepository.GetRefreshToken(context.Background(), refreshToken)
	if err != nil {
		fmt.Printf("Error getting refresh token from DB: %v\n", err)
		return nil, fmt.Errorf("failed to get refresh token: %v", err)
	}

	// Проверка использования токена
	if tokenData.Used {
		fmt.Printf("Refresh token already used\n")
		return nil, fmt.Errorf("refresh token already used")
	}

	// Создание новой пары токенов
	newTokens, err := as.CreateTokenPair(context.Background(), tokenData.UserID, clientIP)
	if err != nil {
		fmt.Printf("Error creating new token pair: %v\n", err)
		return nil, fmt.Errorf("failed to create new token pair: %v", err)
	}

	// Отметка старого токена как использованного
	tokenData.Used = true
	if err := as.tokenRepository.UpdateRefreshToken(context.Background(), tokenData); err != nil {
		fmt.Printf("Error updating refresh token in DB: %v\n", err)
		return nil, fmt.Errorf("failed to update refresh token: %v", err)
	}

	return newTokens, nil
}

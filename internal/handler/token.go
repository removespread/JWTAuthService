package handler

import (
	"fmt"
	"juniortest/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

// -----------------------------------------------------------------------------------------------
// Комментарии для объяснения своих действий, а также лучшего понимания кода | t.me/fakelag
// -----------------------------------------------------------------------------------------------

// AuthHandler - структура для обработки запросов, связанных с аутентификацией
type AuthHandler struct {
	authService *service.AuthService
}

// NewAuthHandler - конструктор для AuthHandler
func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// GetTokens - обработчик для получения токенов
func (h *AuthHandler) GetTokens(c *gin.Context) {
	userID := c.Param("user_id")

	fmt.Printf("Получен запрос с user_id: '%s'\n", userID)
	fmt.Printf("Все параметры запроса: %v\n", c.Request.URL.Query())

	// Проверка наличия user_id в запросе
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	// Получение IP-адреса клиента
	clientIP := c.ClientIP()

	// Получение токенов, обращение к слою сервисов
	tokens, err := h.authService.GetTokens(userID, clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue tokens"})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// Структура для получения refresh_token из запроса
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	// Проверка валидности запроса
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Получение IP-адреса клиента
	clientIP := c.ClientIP()

	// Обновление токенов, обращение к слою сервисов
	tokens, err := h.authService.RefreshToken(request.RefreshToken, clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh token"})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

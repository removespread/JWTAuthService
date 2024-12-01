package main

import (
	"fmt"
	"juniortest/internal/config"
	"juniortest/internal/handler"
	"juniortest/internal/models"
	"juniortest/internal/repository"
	"juniortest/internal/service"
	"log"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

func main() {
	// Инициализация конфига
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Инициализация репозитория для работы с токенами
	tokenRepo := repository.NewTokenRepository(cfg.Database.DB)

	// Инициализация сервиса аутентификации
	authService := service.NewAuthService(tokenRepo, []byte(cfg.JWTSecretKey))

	// Инициализация обработчика аутентификации
	authHandler := handler.NewAuthHandler(authService)

	// Создание роутера Gin
	router := gin.Default()

	// Определение маршрутов
	router.GET("/tokens", authHandler.GetTokens)
	router.POST("/refresh", authHandler.RefreshToken)

	// Маршрут на проверку жизни
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "ok",
		})
	})

	// test router
	router.GET("/debug/tokens", func(c *gin.Context) {
		rows, err := cfg.Database.DB.Query("SELECT * FROM refresh_tokens")
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		var tokens []models.RefreshTokenData
		for rows.Next() {
			var token models.RefreshTokenData
			err := rows.Scan(
				&token.ID,
				&token.UserID,
				&token.TokenHash,
				&token.ClientIP,
				&token.AccessTokenID,
				&token.CreatedAt,
				&token.ExpiresAt,
				&token.Used,
			)
			if err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
			tokens = append(tokens, token)
		}

		if err = rows.Err(); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, tokens)
	})

	// Запуск сервера
	serverAddr := ":8080" // Можно вынести в конфиг, но не стал т.к это тестовое, плюс так легче :)
	fmt.Printf("Server starting on %s\n", serverAddr)
	if err := router.Run(serverAddr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

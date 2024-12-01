package repository

import (
	"context"
	"database/sql"
	"fmt"
	"juniortest/internal/models"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// -----------------------------------------------------------------------------------------------
// Комментарии для объяснения своих действий, а также лучшего понимания кода | t.me/fakelag
// -----------------------------------------------------------------------------------------------

// Описание интерфейса для работы с токенами
type TokenRepository interface {
	SaveRefreshToken(ctx context.Context, token *models.RefreshTokenData) error              // Сохранение RefreshToken в базе данных
	GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshTokenData, error) // Получение RefreshToken из базы данных по хэшу
	UpdateRefreshToken(ctx context.Context, token *models.RefreshTokenData) error            // Обновление RefreshToken в базе данных
}

// Реализация структуры для работы с токенами
type tokenRepository struct {
	db *sql.DB
}

// Создание нового экземпляра TokenRepository, внутри которого будет происходить работа с базой данных
func NewTokenRepository(db *sql.DB) TokenRepository {
	return &tokenRepository{db: db}
}

// Сохранение RefreshToken в базе данных
func (r *tokenRepository) SaveRefreshToken(ctx context.Context, token *models.RefreshTokenData) error {
	fmt.Printf("SaveRefreshToken called with token ID: %s\n", token.ID)

	// SQL запрос
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, client_ip, access_token_id, created_at, expires_at, used)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	// Выполнение запроса, если ошибка, то возвращаем её
	result, err := r.db.ExecContext(ctx, query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.ClientIP,
		token.AccessTokenID,
		token.CreatedAt,
		token.ExpiresAt,
		token.Used,
	)

	if err != nil {
		fmt.Printf("Database error: %v\n", err)
		return fmt.Errorf("database error: %v", err)
	}

	rows, err := result.RowsAffected()
	fmt.Printf("Rows affected: %d\n", rows)

	return err
}

// Получение RefreshToken из базы данных по хэшу
func (r *tokenRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshTokenData, error) {
	fmt.Printf("Getting refresh tokens from DB for hash: %s\n", tokenHash)

	// SQL-запрос
	query := `
		SELECT id, user_id, token_hash, client_ip, access_token_id, created_at, expires_at, used 
		FROM refresh_tokens 
		WHERE used = false AND expires_at > NOW()
	`

	// Выполнение запроса, если ошибка, то возвращаем её
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("database query error: %v", err)
	}
	defer rows.Close()

	// Цикл для получения данных из базы данных
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
			fmt.Printf("Error scanning row: %v\n", err)
			continue
		}

		// Сравниваем хэши с помощью bcrypt
		err = bcrypt.CompareHashAndPassword([]byte(token.TokenHash), []byte(tokenHash))
		if err == nil {
			fmt.Printf("Found matching refresh token with ID: %s\n", token.ID)
			return &token, nil
		}
		fmt.Printf("Token hash comparison failed: %v\n", err)
	}

	// Проверка ошибок при итерации строк
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %v", err)
	}

	return nil, fmt.Errorf("no valid refresh token found")
}

// Отметка RefreshToken как использованного
func (r *tokenRepository) MarkTokenAsUsed(ctx context.Context, tokenID uuid.UUID) error {
	// SQL запрос
	query := `UPDATE refresh_tokens SET used = true WHERE id = $1`
	// Выполнение запроса, если ошибка, то возвращаем её
	_, err := r.db.ExecContext(ctx, query, tokenID)
	return err
}

// Обновление RefreshToken в базе данных
func (r *tokenRepository) UpdateRefreshToken(ctx context.Context, token *models.RefreshTokenData) error {
	// SQL запрос
	query := `
		UPDATE refresh_tokens 
		SET used = $1, access_token_id = $2
		WHERE id = $3
	`
	// Выполнение запроса, если ошибка, то возвращаем её
	_, err := r.db.ExecContext(ctx, query, token.Used, token.AccessTokenID, token.ID)
	return err
}

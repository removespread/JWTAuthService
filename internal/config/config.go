package config

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// -----------------------------------------------------------------------------------------------
// Комментарии для объяснения своих действий, а также лучшего понимания кода | t.me/fakelag
// -----------------------------------------------------------------------------------------------

// Конфиг базы данных
type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"db_name"`
	DB       *sql.DB
}

// Конфиг токенов
// Можно было закинуть эту структуру в конфиг приложения, но я решил сделать отдельной, чтобы было проще читать код
type TokenExpiry struct {
	AccessToken  string `yaml:"access_token"`
	RefreshToken string `yaml:"refresh_token"`
}

// Конфиг приложения
type Config struct {
	Database     DatabaseConfig `yaml:"database"`
	JWTSecretKey string         `yaml:"jwt_secret_key"`
	TokenExpiry  TokenExpiry    `yaml:"token_expiry"`
}

// Загрузка конфига
func LoadConfig() (*Config, error) {
	// Чтение конфига из файла config.yml
	data, err := os.ReadFile("configs/config.yml")
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Декодирование конфига
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Формирование строки подключения к БД
	databaseConnectionString := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.Database.Host,
		config.Database.Port,
		config.Database.User,
		config.Database.Password,
		config.Database.DBName,
	)

	// Подключение к БД
	db, err := sql.Open("postgres", databaseConnectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	config.Database.DB = db

	// Пинг БД
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Парсинг длительности двух токенов
	accessDuration, err := time.ParseDuration(config.TokenExpiry.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse access token duration: %w", err)
	}

	refreshDuration, err := time.ParseDuration(config.TokenExpiry.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token duration: %w", err)
	}

	// Отдаем конфиг
	return &Config{
		Database:     config.Database,
		JWTSecretKey: config.JWTSecretKey,
		TokenExpiry: TokenExpiry{
			AccessToken:  accessDuration.String(),
			RefreshToken: refreshDuration.String(),
		},
	}, nil
}

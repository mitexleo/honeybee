package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds all configuration values
type Config struct {
	Server struct {
		Host string
		Port int
	}
	Database struct {
		Path string
	}
	Admin struct {
		Username string
		Password string
	}
	JWT struct {
		Secret string
	}
	GeoIP struct {
		Path string
	}
	MaxLogSize  int
	BackupCount int
}

// LoadConfig loads configuration from .env file and validates required fields
func LoadConfig() (*Config, error) {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		// .env not found, use environment variables
	}

	cfg := &Config{}

	// Server config
	cfg.Server.Host = getEnv("SERVER_HOST", "0.0.0.0")
	portStr := getEnv("SERVER_PORT", "5000")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid SERVER_PORT: %v", err)
	}
	cfg.Server.Port = port

	// Database config
	cfg.Database.Path = getEnv("HONEYPOT_DB_PATH", "data/honeypot.db")

	// Admin config (required)
	cfg.Admin.Username = getEnv("ADMIN_USERNAME", "admin")
	cfg.Admin.Password = getEnv("ADMIN_PASSWORD", "")
	if cfg.Admin.Password == "" {
		return nil, fmt.Errorf("ADMIN_PASSWORD is required")
	}

	// JWT config (required)
	cfg.JWT.Secret = getEnv("JWT_SECRET", "")
	if cfg.JWT.Secret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	// GeoIP config
	cfg.GeoIP.Path = getEnv("GEOIP_DB_PATH", "GeoLite2-City.mmdb")

	// Other configs
	maxLogStr := getEnv("MAX_LOG_SIZE", "10485760")
	maxLog, err := strconv.Atoi(maxLogStr)
	if err != nil {
		return nil, fmt.Errorf("invalid MAX_LOG_SIZE: %v", err)
	}
	cfg.MaxLogSize = maxLog

	backupStr := getEnv("BACKUP_COUNT", "5")
	backup, err := strconv.Atoi(backupStr)
	if err != nil {
		return nil, fmt.Errorf("invalid BACKUP_COUNT: %v", err)
	}
	cfg.BackupCount = backup

	return cfg, nil
}

// GetDatabasePath returns the database path from config
func GetDatabasePath() string {
	return getEnv("HONEYPOT_DB_PATH", "data/honeypot.db")
}

// getEnv gets environment variable with default
func getEnv(key, defaultVal string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultVal
}

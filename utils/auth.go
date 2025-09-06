package utils

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	JwtSecret     = []byte(os.Getenv("JWT_SECRET"))
	AdminUsername = os.Getenv("ADMIN_USERNAME")
	AdminPassword = os.Getenv("ADMIN_PASSWORD")
)

func init() {
	if len(JwtSecret) == 0 {
		JwtSecret = []byte("your_jwt_secret_key")
	}
	if AdminUsername == "" {
		AdminUsername = "admin"
	}
	if AdminPassword == "" {
		AdminPassword = "change_this_password"
	}
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// GenerateJWT creates a new JWT token for the given username
func GenerateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JwtSecret)
	return tokenString, err
}

// ValidateJWT checks if a JWT token is valid and returns the username
func ValidateJWT(tokenString string) (string, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return JwtSecret, nil
	})
	if err != nil {
		return "", err
	}
	if !token.Valid {
		return "", jwt.ErrSignatureInvalid
	}
	return claims.Username, nil
}

// Claims struct for JWT
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// AuthenticateUser checks if provided credentials are valid
func AuthenticateUser(username, password string) bool {
	if username == AdminUsername {
		// First try to compare as bcrypt hash
		err := bcrypt.CompareHashAndPassword([]byte(AdminPassword), []byte(password))
		if err == nil {
			return true
		}

		// If that fails, check if AdminPassword is plain text (for backward compatibility)
		if AdminPassword == password {
			return true
		}

		// Debug: log authentication attempt details
		fmt.Printf("Auth failed: username=%s, provided_pass=%s, stored_pass=%s, bcrypt_err=%v\n",
			username, password, AdminPassword, err)
	}
	return false
}

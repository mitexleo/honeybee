package utils

import (
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"honeybee/models"

	"github.com/gin-gonic/gin"
	"github.com/oschwald/maxminddb-golang"
	"golang.org/x/crypto/bcrypt"
)

var (
	secretKey = getEnv("SECRET_KEY", "random_secret_key_for_hashing")
	geoDB     *maxminddb.Reader
)

func getEnv(key, defaultVal string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultVal
}

func InitGeoDB(geoPath string) {
	if geoPath == "" {
		geoPath = "GeoLite2-City.mmdb"
	}
	if geoPath != "" {
		var err error
		geoDB, err = maxminddb.Open(geoPath)
		if err != nil {
			// Log error, but don't fail
		}
	}
}

// GetClientIP extracts the real client IP from the request
func GetClientIP(c *gin.Context) string {
	headers := []string{"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "CF-Connecting-IP"}
	for _, header := range headers {
		if ip := strings.Split(c.GetHeader(header), ",")[0]; ip != "" {
			return strings.TrimSpace(ip)
		}
	}
	return c.ClientIP()
}

// GetGeolocation returns country, city, lat, lon for an IP
func GetGeolocation(ip string) (string, string, float64, float64) {
	if geoDB == nil {
		return "", "", 0, 0
	}
	var record struct {
		Country struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Location struct {
			Latitude  float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}
	err := geoDB.Lookup(net.ParseIP(ip), &record)
	if err != nil {
		return "", "", 0, 0
	}
	return record.Country.Names["en"], record.City.Names["en"], record.Location.Latitude, record.Location.Longitude
}

// SanitizeInput cleans user input
func SanitizeInput(data string, maxLen int) string {
	if len(data) > maxLen {
		data = data[:maxLen]
	}
	data = strings.ReplaceAll(data, "<", "&lt;")
	data = strings.ReplaceAll(data, ">", "&gt;")
	return data
}

// ValidateSessionID checks if session ID is valid
func ValidateSessionID(sessionID string) bool {
	if len(sessionID) < 10 || len(sessionID) > 100 {
		return false
	}
	sessionIDRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	return sessionIDRegex.MatchString(sessionID)
}

// UpdateOrCreateSession manages session records
func UpdateOrCreateSession(sessionID, ip, userAgent string) {
	var session models.Session
	now := time.Now()
	country, city, lat, lon := GetGeolocation(ip)

	if err := models.DB.Where("session_id = ?", sessionID).First(&session).Error; err != nil {
		session = models.Session{
			SessionID: sessionID,
			IPAddress: ip,
			UserAgent: userAgent,
			FirstSeen: now,
			LastSeen:  now,
			Country:   country,
			City:      city,
			Latitude:  lat,
			Longitude: lon,
		}
		models.DB.Create(&session)
	} else {
		session.LastSeen = now
		models.DB.Save(&session)
	}
}

// ValidatePassword compares hashed password
func ValidatePassword(hashed, plain string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	return err == nil
}

package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"archive/zip"
	"bytes"
	"encoding/csv"

	"github.com/gin-gonic/gin"
	"github.com/oschwald/maxminddb-golang"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	db            *gorm.DB
	geoDB         *maxminddb.Reader
	adminUsername string
	adminPassword string
	secretKey     string
	databasePath  = getEnv("HONEYPOT_DB_PATH", "honeypot.db")
	logFile       = getEnv("HONEYPOT_LOG_FILE", "honeypot.log")
	geoipDatabase = getEnv("GEOIP_DB_PATH", "GeoLite2-City.mmdb")
	maxLogSize    = getEnvInt("MAX_LOG_SIZE", 10*1024*1024)
	backupCount   = getEnvInt("BACKUP_COUNT", 5)
	maxContentLen = getEnvInt("MAX_CONTENT_LENGTH", 1024*1024)
)

func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultVal
}

// Models
type Session struct {
	ID           uint   `gorm:"primaryKey"`
	SessionID    string `gorm:"unique;not null"`
	IPAddress    string `gorm:"not null"`
	UserAgent    string
	FirstSeen    time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	LastSeen     time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	Country      string
	City         string
	Latitude     float64
	Longitude    float64
	IsSuspicious int `gorm:"default:0"`
}

type LoginAttempt struct {
	ID             uint      `gorm:"primaryKey"`
	SessionID      string    `gorm:"not null"`
	AttemptNumber  int       `gorm:"not null"`
	Username       string    `gorm:"not null"`
	PasswordHash   string    `gorm:"not null"`
	RememberMe     bool      `gorm:"default:false"`
	Timestamp      time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	IPAddress      string    `gorm:"not null"`
	UserAgent      string
	Referrer       string
	MouseMovements string
	FormFillTime   int
	ScreenInfo     string
	BrowserInfo    string
	Timezone       string
	Plugins        string
	DoNotTrack     string
	Keystrokes     string
	FocusEvents    string
	Success        bool `gorm:"default:false"`
}

type RegistrationAttempt struct {
	ID                   uint      `gorm:"primaryKey"`
	SessionID            string    `gorm:"not null"`
	AttemptNumber        int       `gorm:"not null"`
	Fullname             string    `gorm:"not null"`
	Email                string    `gorm:"not null"`
	Username             string    `gorm:"not null"`
	PasswordHash         string    `gorm:"not null"`
	TermsAccepted        bool      `gorm:"default:false"`
	NewsletterSubscribed bool      `gorm:"default:false"`
	Timestamp            time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	IPAddress            string    `gorm:"not null"`
	UserAgent            string
	Referrer             string
	MouseMovements       string
	FormFillTime         int
	ScreenInfo           string
	BrowserInfo          string
	Timezone             string
	Plugins              string
	DoNotTrack           string
	Keystrokes           string
	FocusEvents          string
}

type ActivityLog struct {
	ID           uint   `gorm:"primaryKey"`
	SessionID    string `gorm:"not null"`
	ActivityType string `gorm:"not null"`
	Data         string
	Timestamp    time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	IPAddress    string    `gorm:"not null"`
}

type Fingerprint struct {
	ID        uint      `gorm:"primaryKey"`
	SessionID string    `gorm:"not null"`
	Data      string    `gorm:"not null"`
	Timestamp time.Time `gorm:"default:CURRENT_TIMESTAMP"`
}

func initDatabase() error {
	var err error
	dsn := databasePath + "?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=1000&_temp_store=MEMORY"
	db, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return err
	}

	// AutoMigrate models
	err = db.AutoMigrate(&Session{}, &LoginAttempt{}, &RegistrationAttempt{}, &ActivityLog{}, &Fingerprint{})
	if err != nil {
		return err
	}

	// Create indexes
	sqlDB, _ := db.DB()
	sqlDB.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip_address);")
	sqlDB.Exec("CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address);")
	sqlDB.Exec("CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(timestamp);")
	sqlDB.Exec("CREATE INDEX IF NOT EXISTS idx_activity_log_time ON activity_log(timestamp);")

	return nil
}

func initGeoDB() error {
	var err error
	geoDB, err = maxminddb.Open(geoipDatabase)
	return err
}

func getClientIP(c *gin.Context) string {
	headers := []string{"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "CF-Connecting-IP"}
	for _, header := range headers {
		ip := strings.Split(c.GetHeader(header), ",")[0]
		ip = strings.TrimSpace(ip)
		if ip != "" {
			return ip
		}
	}
	return c.ClientIP()
}

type GeoLocation struct {
	Country   string  `maxminddb:"country"`
	City      string  `maxminddb:"city"`
	Latitude  float64 `maxminddb:"latitude"`
	Longitude float64 `maxminddb:"longitude"`
}

func getGeolocation(ip string) (string, string, float64, float64) {
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

func hashPassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash)
}

func sanitizeInput(data string, maxLen int) string {
	if len(data) > maxLen {
		data = data[:maxLen]
	}
	// Simple sanitization (replace with bleach equivalent if needed)
	data = strings.ReplaceAll(data, "<", "&lt;")
	data = strings.ReplaceAll(data, ">", "&gt;")
	return data
}

var sessionIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func validateSessionID(sessionID string) bool {
	if len(sessionID) < 10 || len(sessionID) > 100 {
		return false
	}
	return sessionIDRegex.MatchString(sessionID)
}

func requireAdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		username, password, hasAuth := c.Request.BasicAuth()
		if !hasAuth || subtle.ConstantTimeCompare([]byte(username), []byte(adminUsername)) != 1 || subtle.ConstantTimeCompare([]byte(password), []byte(adminPassword)) != 1 {
			c.Header("WWW-Authenticate", `Basic realm="Honeypot Admin"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			return
		}
		c.Next()
	}
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.google-analytics.com; script-src-elem 'self' 'unsafe-inline' https://www.googletagmanager.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https://www.google-analytics.com https://www.googletagmanager.com; connect-src 'self' *; font-src 'self' https://fonts.gstatic.com; object-src 'none'; media-src 'none'; frame-src 'none';")
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}

func logHoneypotActivity(c *gin.Context) {
	if c.Request.Method == "OPTIONS" {
		c.Status(http.StatusOK)
		return
	}

	var data map[string]interface{}
	if err := c.BindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	activityType, _ := data["type"].(string)
	activityData, _ := data["data"].(interface{})

	if activityType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Activity type required"})
		return
	}

	ipAddress := getClientIP(c)
	userAgent := sanitizeInput(c.GetHeader("User-Agent"), 500)

	if activityType == "batch" {
		batch, ok := activityData.([]interface{})
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Batch data must be a list"})
			return
		}

		for _, item := range batch {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			itemType, _ := itemMap["type"].(string)
			itemData, _ := itemMap["data"].(map[string]interface{})
			if itemType == "" {
				continue
			}
			sessionID, _ := itemData["session_id"].(string)
			if !validateSessionID(sessionID) {
				continue
			}

			updateOrCreateSession(sessionID, ipAddress, userAgent)

			switch itemType {
			case "login_attempt":
				logLoginAttempt(itemData, ipAddress)
			case "registration_attempt":
				logRegistrationAttempt(itemData, ipAddress)
			case "fingerprint":
				logFingerprint(sessionID, itemData, ipAddress)
			default:
				logGeneralActivity(sessionID, itemType, itemData, ipAddress)
			}
			log.Printf("HONEYPOT %s: %s from %s", itemType, sessionID, ipAddress)
		}
		c.JSON(http.StatusOK, gin.H{"status": "batch logged"})
		return
	}

	// Non-batch
	dataMap, ok := activityData.(map[string]interface{})
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid data"})
		return
	}
	sessionID, _ := dataMap["session_id"].(string)
	if !validateSessionID(sessionID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID"})
		return
	}

	updateOrCreateSession(sessionID, ipAddress, userAgent)

	var success bool
	switch activityType {
	case "login_attempt":
		success = logLoginAttempt(dataMap, ipAddress)
	case "registration_attempt":
		success = logRegistrationAttempt(dataMap, ipAddress)
	case "fingerprint":
		success = logFingerprint(sessionID, dataMap, ipAddress)
	default:
		success = logGeneralActivity(sessionID, activityType, dataMap, ipAddress)
	}

	if !success {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to log activity"})
		return
	}

	log.Printf("HONEYPOT %s: %s from %s", activityType, sessionID, ipAddress)
	c.JSON(http.StatusOK, gin.H{"status": "logged"})
}

func updateOrCreateSession(sessionID, ip, userAgent string) {
	var session Session
	now := time.Now()
	country, city, lat, lon := getGeolocation(ip)

	if err := db.Where("session_id = ?", sessionID).First(&session).Error; err == gorm.ErrRecordNotFound {
		session = Session{
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
		db.Create(&session)
	} else {
		session.LastSeen = now
		db.Save(&session)
	}
}

func logLoginAttempt(data map[string]interface{}, ip string) bool {
	attempt := LoginAttempt{
		SessionID:      sanitizeInput(data["session_id"].(string), 100),
		AttemptNumber:  int(data["attempt_number"].(float64)),
		Username:       sanitizeInput(data["username"].(string), 255),
		PasswordHash:   hashPassword(data["password"].(string)),
		RememberMe:     data["remember_me"].(bool),
		IPAddress:      ip,
		UserAgent:      sanitizeInput(data["user_agent"].(string), 500),
		Referrer:       sanitizeInput(data["referrer"].(string), 500),
		MouseMovements: jsonString(data["mouse_movements"]),
		FormFillTime:   int(data["form_fill_time"].(float64)),
		ScreenInfo:     jsonString(data["screen_info"]),
		BrowserInfo:    jsonString(data["browser_info"]),
		Timezone:       sanitizeInput(data["timezone"].(string), 50),
		Plugins:        jsonString(data["plugins"]),
		DoNotTrack:     sanitizeInput(data["doNotTrack"].(string), 10),
		Keystrokes:     jsonString(data["keystrokes"]),
		FocusEvents:    jsonString(data["focus_events"]),
	}
	if db.Create(&attempt).Error != nil {
		return false
	}
	return true
}

func logRegistrationAttempt(data map[string]interface{}, ip string) bool {
	attempt := RegistrationAttempt{
		SessionID:            sanitizeInput(data["session_id"].(string), 100),
		AttemptNumber:        int(data["attempt_number"].(float64)),
		Fullname:             sanitizeInput(data["fullname"].(string), 255),
		Email:                sanitizeInput(data["email"].(string), 255),
		Username:             sanitizeInput(data["username"].(string), 255),
		PasswordHash:         hashPassword(data["password"].(string)),
		TermsAccepted:        data["terms_accepted"].(bool),
		NewsletterSubscribed: data["newsletter_subscribed"].(bool),
		IPAddress:            ip,
		UserAgent:            sanitizeInput(data["user_agent"].(string), 500),
		Referrer:             sanitizeInput(data["referrer"].(string), 500),
		MouseMovements:       jsonString(data["mouse_movements"]),
		FormFillTime:         int(data["form_fill_time"].(float64)),
		ScreenInfo:           jsonString(data["screen_info"]),
		BrowserInfo:          jsonString(data["browser_info"]),
		Timezone:             sanitizeInput(data["timezone"].(string), 50),
		Plugins:              jsonString(data["plugins"]),
		DoNotTrack:           sanitizeInput(data["doNotTrack"].(string), 10),
		Keystrokes:           jsonString(data["keystrokes"]),
		FocusEvents:          jsonString(data["focus_events"]),
	}
	if db.Create(&attempt).Error != nil {
		return false
	}
	return true
}

func logGeneralActivity(sessionID, activityType string, data map[string]interface{}, ip string) bool {
	dataJSON, _ := json.Marshal(data)
	activity := ActivityLog{
		SessionID:    sessionID,
		ActivityType: activityType,
		Data:         string(dataJSON),
		IPAddress:    ip,
	}
	if db.Create(&activity).Error != nil {
		return false
	}
	return true
}

func logFingerprint(sessionID string, data map[string]interface{}, ip string) bool {
	dataJSON, _ := json.Marshal(data)
	fp := Fingerprint{
		SessionID: sessionID,
		Data:      string(dataJSON),
	}
	if db.Create(&fp).Error != nil {
		return false
	}
	return true
}

func jsonString(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func setupRouter() *gin.Engine {
	r := gin.Default()
	r.Use(securityHeaders())
	r.MaxMultipartMemory = int64(maxContentLen)

	// Static routes
	r.StaticFile("/", "./frontend/index.html")
	r.StaticFile("/register.html", "./frontend/register.html")
	r.StaticFile("/styles.css", "./frontend/styles.css")
	r.StaticFile("/script.js", "./frontend/script.js")
	r.StaticFile("/register.js", "./frontend/register.js")
	r.StaticFile("/dashboard.html", "./dashboard.html") // Assuming it's in root, or move to frontend

	r.GET("/health", func(c *gin.Context) {
		// Health check
		sqlDB, _ := db.DB()
		if err := sqlDB.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "error": "Database connection failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "healthy", "timestamp": time.Now().UTC().Format(time.RFC3339)})
	})

	r.POST("/api/honeypot/log", logHoneypotActivity)
	r.OPTIONS("/api/honeypot/log", logHoneypotActivity)

	r.GET("/api/client-ip", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ip": getClientIP(c)})
	})

	r.GET("/api/metrics", requireAdminAuth(), func(c *gin.Context) {
		// Implement metrics similarly to Python
		var metrics struct {
			Login24h     int
			Reg24h       int
			Sessions24h  int
			UniqueIPs24h int
		}
		db.Raw(`SELECT
			(SELECT COUNT(*) FROM login_attempts WHERE timestamp > datetime('now', '-24 hours')) as login_24h,
			(SELECT COUNT(*) FROM registration_attempts WHERE timestamp > datetime('now', '-24 hours')) as reg_24h,
			(SELECT COUNT(*) FROM sessions WHERE last_seen > datetime('now', '-24 hours')) as sessions_24h,
			(SELECT COUNT(DISTINCT ip_address) FROM sessions WHERE last_seen > datetime('now', '-24 hours')) as unique_ips_24h`).Scan(&metrics)
		metricsText := fmt.Sprintf(`
# HELP honeypot_login_attempts_24h Login attempts in last 24 hours
# TYPE honeypot_login_attempts_24h counter
honeypot_login_attempts_24h %d

# HELP honeypot_registration_attempts_24h Registration attempts in last 24 hours
# TYPE honeypot_registration_attempts_24h counter
honeypot_registration_attempts_24h %d

# HELP honeypot_sessions_24h Active sessions in last 24 hours
# TYPE honeypot_sessions_24h gauge
honeypot_sessions_24h %d

# HELP honeypot_unique_ips_24h Unique IP addresses in last 24 hours
# TYPE honeypot_unique_ips_24h gauge
honeypot_unique_ips_24h %d
`, metrics.Login24h, metrics.Reg24h, metrics.Sessions24h, metrics.UniqueIPs24h)
		c.String(http.StatusOK, metricsText)
	})

	// Admin routes
	admin := r.Group("/")
	admin.Use(requireAdminAuth())

	admin.GET("/admin", func(c *gin.Context) { c.File("./frontend/dashboard.html") })
	admin.GET("/dashboard", func(c *gin.Context) { c.File("./frontend/dashboard.html") })

	admin.GET("/api/dashboard/data", getDashboardData)

	admin.GET("/api/export/csv", exportCSV)
	admin.GET("/api/export/json", exportJSON)

	// Static file serving with security
	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		allowedExt := []string{".html", ".css", ".js", ".ico", ".txt", ".svg", ".webp"}
		for _, ext := range allowedExt {
			if strings.HasSuffix(path, ext) && !strings.Contains(path, "..") && !strings.HasPrefix(path, "/") {
				filePath := filepath.Join("frontend", path[1:])
				if _, err := os.Stat(filePath); err == nil {
					c.File(filePath)
					return
				}
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
	})

	return r
}

// Implement getDashboardData, exportCSV, exportJSON similar to Python's export_utils.py and routes.py
// For brevity, sketch one

func getDashboardData(c *gin.Context) {
	var stats struct {
		TotalSessions  int
		UniqueIPs      int
		Countries      int
		RecentSessions int
		Sessions24h    int
		TotalAttacks   int
	}
	db.Raw(`
		SELECT
			COUNT(*) as total_sessions,
			COUNT(DISTINCT ip_address) as unique_ips,
			COUNT(DISTINCT country) as countries,
			COUNT(CASE WHEN last_seen > datetime('now', '-1 hour') THEN 1 END) as recent_sessions,
			COUNT(CASE WHEN last_seen > datetime('now', '-24 hours') THEN 1 END) as sessions_24h
		FROM sessions
	`).Scan(&stats)

	var totalAttacks int
	db.Raw(`
		SELECT
			(SELECT COUNT(*) FROM login_attempts) +
			(SELECT COUNT(*) FROM registration_attempts) as total_attacks
	`).Scan(&totalAttacks)
	stats.TotalAttacks = totalAttacks

	var topIPs []struct {
		IPAddress string
		Attempts  int
		Country   string
		City      string
	}
	db.Raw(`
		SELECT
			la.ip_address,
			COUNT(*) as attempts,
			s.country,
			s.city
		FROM login_attempts la
		LEFT JOIN sessions s ON la.session_id = s.session_id
		WHERE la.timestamp > datetime('now', '-7 days')
		GROUP BY la.ip_address
		ORDER BY attempts DESC
		LIMIT 10
	`).Scan(&topIPs)

	var loginAttempts []LoginAttempt
	db.Joins("LEFT JOIN sessions s ON login_attempts.session_id = s.session_id").
		Select("login_attempts.*, s.country").
		Order("login_attempts.timestamp DESC").
		Limit(50).
		Find(&loginAttempts)

	var registrationAttempts []RegistrationAttempt
	db.Joins("LEFT JOIN sessions s ON registration_attempts.session_id = s.session_id").
		Select("registration_attempts.*, s.country").
		Order("registration_attempts.timestamp DESC").
		Limit(50).
		Find(&registrationAttempts)

	c.JSON(http.StatusOK, gin.H{
		"stats":                 stats,
		"top_ips":               topIPs,
		"login_attempts":        loginAttempts,
		"registration_attempts": registrationAttempts,
		"timestamp":             time.Now().UTC().Format(time.RFC3339),
	})
}

func exportCSV(c *gin.Context) {
	exportType := c.DefaultQuery("type", "all")
	daysBackStr := c.DefaultQuery("days", "30")
	daysBack, _ := strconv.Atoi(daysBackStr)
	if daysBack > 90 {
		daysBack = 90
	}

	switch exportType {
	case "login":
		var attempts []LoginAttempt
		db.Where("timestamp > datetime('now', ?)", fmt.Sprintf("-%d days", daysBack)).
			Order("timestamp DESC").
			Find(&attempts)

		b := &bytes.Buffer{}
		w := csv.NewWriter(b)
		w.Write([]string{"Timestamp", "SessionID", "AttemptNumber", "Username", "PasswordHash", "RememberMe", "IPAddress", "UserAgent", "Referrer", "MouseMovements", "FormFillTime", "ScreenInfo", "BrowserInfo", "Timezone", "Plugins", "DoNotTrack", "Keystrokes", "FocusEvents"})
		for _, a := range attempts {
			w.Write([]string{
				a.Timestamp.String(), a.SessionID, strconv.Itoa(a.AttemptNumber), a.Username, a.PasswordHash, strconv.FormatBool(a.RememberMe), a.IPAddress, a.UserAgent, a.Referrer, a.MouseMovements, strconv.Itoa(a.FormFillTime), a.ScreenInfo, a.BrowserInfo, a.Timezone, a.Plugins, a.DoNotTrack, a.Keystrokes, a.FocusEvents,
			})
		}
		w.Flush()
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=login_attempts_%s.csv", time.Now().Format("20060102_150405")))
		c.Header("Content-Type", "text/csv")
		c.Data(http.StatusOK, "text/csv", b.Bytes())

	case "register":
		// Similar to login, implement for RegistrationAttempt

	case "sessions":
		// Implement for Session

	case "all":
		buf := new(bytes.Buffer)
		zipWriter := zip.NewWriter(buf)

		// Add login_attempts.csv
		loginFile, _ := zipWriter.Create("login_attempts.csv")
		loginWriter := csv.NewWriter(loginFile)
		var attempts []LoginAttempt
		db.Where("timestamp > datetime('now', ?)", fmt.Sprintf("-%d days", daysBack)).
			Order("timestamp DESC").
			Find(&attempts)

		loginWriter.Write([]string{"Timestamp", "SessionID", "AttemptNumber", "Username", "PasswordHash", "RememberMe", "IPAddress", "UserAgent", "Referrer", "MouseMovements", "FormFillTime", "ScreenInfo", "BrowserInfo", "Timezone", "Plugins", "DoNotTrack", "Keystrokes", "FocusEvents"})

		for _, a := range attempts {
			loginWriter.Write([]string{
				a.Timestamp.String(), a.SessionID, strconv.Itoa(a.AttemptNumber), a.Username, a.PasswordHash, strconv.FormatBool(a.RememberMe), a.IPAddress, a.UserAgent, a.Referrer, a.MouseMovements, strconv.Itoa(a.FormFillTime), a.ScreenInfo, a.BrowserInfo, a.Timezone, a.Plugins, a.DoNotTrack, a.Keystrokes, a.FocusEvents,
			})
		}
		loginWriter.Flush()

		// Add other CSVs: registration, sessions, activity_log

		zipWriter.Close()

		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=honeypot_data_%s.zip", time.Now().Format("20060102_150405")))
		c.Header("Content-Type", "application/zip")
		c.Data(http.StatusOK, "application/zip", buf.Bytes())

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid export type"})
	}
}

func exportJSON(c *gin.Context) {
	daysBackStr := c.DefaultQuery("days", "30")
	daysBack, _ := strconv.Atoi(daysBackStr)
	if daysBack > 90 {
		daysBack = 90
	}

	data := map[string]interface{}{
		"export_timestamp":   time.Now().UTC().Format(time.RFC3339),
		"export_period_days": daysBack,
	}

	var sessions []Session
	db.Where("last_seen > datetime('now', ?)", fmt.Sprintf("-%d days", daysBack)).
		Order("last_seen DESC").
		Find(&sessions)
	data["sessions"] = sessions

	// Similarly for login_attempts, registration_attempts, activity_log (limited)

	c.JSON(http.StatusOK, data)
}

func main() {
	adminUsername = getEnv("ADMIN_USERNAME", "admin")
	adminPassword = getEnv("ADMIN_PASSWORD", "change_this_password")
	secretKey = getEnv("SECRET_KEY", "") // Generate if empty

	if err := initDatabase(); err != nil {
		log.Fatal("Database init failed: ", err)
	}
	if err := initGeoDB(); err != nil {
		log.Println("GeoDB init failed: ", err)
	}

	r := setupRouter()
	r.Run(":5000")
}

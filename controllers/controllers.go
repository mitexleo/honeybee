package controllers

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"honeybee/models"
	"honeybee/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// Login handler for JWT authentication
func Login(c *gin.Context) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if creds.Username == utils.AdminUsername && bcrypt.CompareHashAndPassword([]byte(utils.AdminPassword), []byte(creds.Password)) == nil {
		token, err := utils.GenerateJWT(creds.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": token})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}

// Static file routes
func Index(c *gin.Context) {
	c.File("./frontend/index.html")
}

func Register(c *gin.Context) {
	c.File("./frontend/register.html")
}

// Admin login page
func AdminLogin(c *gin.Context) {
	c.File("./frontend/admin-login.html")
}

// Admin dashboard HTML
func AdminDashboardHTML(c *gin.Context) {
	c.File("./frontend/dashboard.html")
}

// Health check
func HealthCheck(c *gin.Context) {
	sqlDB, _ := models.DB.DB()
	if err := sqlDB.Ping(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "error": "Database connection failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "healthy", "timestamp": time.Now().UTC().Format(time.RFC3339)})
}

// Log honeypot activity
func LogHoneypotActivity(c *gin.Context) {
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

	ipAddress := utils.GetClientIP(c)
	userAgent := utils.SanitizeInput(c.GetHeader("User-Agent"), 500)

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
			if !utils.ValidateSessionID(sessionID) {
				continue
			}

			utils.UpdateOrCreateSession(sessionID, ipAddress, userAgent)

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
	if !utils.ValidateSessionID(sessionID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID"})
		return
	}

	utils.UpdateOrCreateSession(sessionID, ipAddress, userAgent)

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

	c.JSON(http.StatusOK, gin.H{"status": "logged"})
}

// Client IP
func GetClientIP(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ip": utils.GetClientIP(c)})
}

// Metrics
func Metrics(c *gin.Context) {
	var metrics struct {
		Login24h     int
		Reg24h       int
		Sessions24h  int
		UniqueIPs24h int
	}
	models.DB.Raw(`
		SELECT
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
}

// Dashboard
func GetDashboardData(c *gin.Context) {
	var stats struct {
		TotalSessions  int
		UniqueIPs      int
		Countries      int
		RecentSessions int
		Sessions24h    int
		TotalAttacks   int
	}
	models.DB.Raw(`
		SELECT
			COUNT(*) as total_sessions,
			COUNT(DISTINCT ip_address) as unique_ips,
			COUNT(DISTINCT country) as countries,
			COUNT(CASE WHEN last_seen > datetime('now', '-1 hour') THEN 1 END) as recent_sessions,
			COUNT(CASE WHEN last_seen > datetime('now', '-24 hours') THEN 1 END) as sessions_24h
		FROM sessions
	`).Scan(&stats)

	var totalAttacks int
	models.DB.Raw(`
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
	models.DB.Raw(`
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

	var loginAttempts []models.LoginAttempt
	models.DB.Where("timestamp > datetime('now', '-7 days')").
		Order("timestamp DESC").
		Limit(50).
		Find(&loginAttempts)

	var registrationAttempts []models.RegistrationAttempt
	models.DB.Where("timestamp > datetime('now', '-7 days')").
		Order("timestamp DESC").
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

// Admin dashboard
func AdminDashboard(c *gin.Context) {
	// Check if this is an API request (has Authorization header)
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		// API request - serve dashboard data
		var stats struct {
			TotalSessions  int
			UniqueIPs      int
			Countries      int
			RecentSessions int
			Sessions24h    int
			TotalAttacks   int
		}
		models.DB.Raw(`
			SELECT
				COUNT(*) as total_sessions,
				COUNT(DISTINCT ip_address) as unique_ips,
				COUNT(DISTINCT country) as countries,
				COUNT(CASE WHEN last_seen > datetime('now', '-1 hour') THEN 1 END) as recent_sessions,
				COUNT(CASE WHEN last_seen > datetime('now', '-24 hours') THEN 1 END) as sessions_24h
			FROM sessions
		`).Scan(&stats)

		var totalAttacks int
		models.DB.Raw(`
			SELECT
				(SELECT COUNT(*) FROM login_attempts) +
				(SELECT COUNT(*) FROM registration_attempts) as total_attacks
		`).Scan(&totalAttacks)
		stats.TotalAttacks = totalAttacks

		c.JSON(http.StatusOK, gin.H{
			"stats":     stats,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// HTML request - serve the dashboard page
	c.File("./frontend/dashboard.html")
}

// Export CSV
func ExportCSV(c *gin.Context) {
	exportType := c.DefaultQuery("type", "all")
	daysBackStr := c.DefaultQuery("days", "30")
	daysBack, _ := strconv.Atoi(daysBackStr)
	if daysBack > 90 {
		daysBack = 90
	}

	switch exportType {
	case "login":
		var attempts []models.LoginAttempt
		models.DB.Where("timestamp > datetime('now', ?)", fmt.Sprintf("-%d days", daysBack)).
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
		// Similar for RegistrationAttempt

	case "sessions":
		// Similar for Session

	case "all":
		buf := new(bytes.Buffer)
		zipWriter := zip.NewWriter(buf)

		// Add login_attempts.csv
		loginFile, _ := zipWriter.Create("login_attempts.csv")
		loginWriter := csv.NewWriter(loginFile)
		var attempts []models.LoginAttempt
		models.DB.Where("timestamp > datetime('now', ?)", fmt.Sprintf("-%d days", daysBack)).
			Order("timestamp DESC").
			Find(&attempts)

		loginWriter.Write([]string{"Timestamp", "SessionID", "AttemptNumber", "Username", "PasswordHash", "RememberMe", "IPAddress", "UserAgent", "Referrer", "MouseMovements", "FormFillTime", "ScreenInfo", "BrowserInfo", "Timezone", "Plugins", "DoNotTrack", "Keystrokes", "FocusEvents"})
		for _, a := range attempts {
			loginWriter.Write([]string{
				a.Timestamp.String(), a.SessionID, strconv.Itoa(a.AttemptNumber), a.Username, a.PasswordHash, strconv.FormatBool(a.RememberMe), a.IPAddress, a.UserAgent, a.Referrer, a.MouseMovements, strconv.Itoa(a.FormFillTime), a.ScreenInfo, a.BrowserInfo, a.Timezone, a.Plugins, a.DoNotTrack, a.Keystrokes, a.FocusEvents,
			})
		}
		loginWriter.Flush()

		zipWriter.Close()

		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=honeypot_data_%s.zip", time.Now().Format("20060102_150405")))
		c.Header("Content-Type", "application/zip")
		c.Data(http.StatusOK, "application/zip", buf.Bytes())

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid export type"})
	}
}

// Export JSON
func ExportJSON(c *gin.Context) {
	daysBackStr := c.DefaultQuery("days", "30")
	daysBack, _ := strconv.Atoi(daysBackStr)
	if daysBack > 90 {
		daysBack = 90
	}

	data := map[string]interface{}{
		"export_timestamp":   time.Now().UTC().Format(time.RFC3339),
		"export_period_days": daysBack,
	}

	var sessions []models.Session
	models.DB.Where("last_seen > datetime('now', ?)", fmt.Sprintf("-%d days", daysBack)).
		Order("last_seen DESC").
		Find(&sessions)
	data["sessions"] = sessions

	// Similarly for login_attempts, registration_attempts, activity_log (limited)

	var loginAttempts []models.LoginAttempt
	models.DB.Where("timestamp > datetime('now', ?)", fmt.Sprintf("-%d days", daysBack)).
		Order("timestamp DESC").
		Limit(1000).
		Find(&loginAttempts)
	data["login_attempts"] = loginAttempts

	var registrationAttempts []models.RegistrationAttempt
	models.DB.Where("timestamp > datetime('now', ?)", fmt.Sprintf("-%d days", daysBack)).
		Order("timestamp DESC").
		Limit(1000).
		Find(&registrationAttempts)
	data["registration_attempts"] = registrationAttempts

	var activityLogs []models.ActivityLog
	models.DB.Where("timestamp > datetime('now', ?)", fmt.Sprintf("-%d days", daysBack)).
		Order("timestamp DESC").
		Limit(5000).
		Find(&activityLogs)
	data["activity_log"] = activityLogs

	c.JSON(http.StatusOK, data)
}

// Internal logging functions (not exported)
func logLoginAttempt(data map[string]interface{}, ip string) bool {
	password := data["password"].(string)
	attempt := models.LoginAttempt{
		SessionID:      utils.SanitizeInput(data["session_id"].(string), 100),
		AttemptNumber:  int(data["attempt_number"].(float64)),
		Username:       utils.SanitizeInput(data["username"].(string), 255),
		PasswordHash:   password,
		RememberMe:     data["remember_me"].(bool),
		IPAddress:      ip,
		UserAgent:      utils.SanitizeInput(data["user_agent"].(string), 500),
		Referrer:       utils.SanitizeInput(data["referrer"].(string), 500),
		MouseMovements: jsonString(data["mouse_movements"]),
		FormFillTime:   int(data["form_fill_time"].(float64)),
		ScreenInfo:     jsonString(data["screen_info"]),
		BrowserInfo:    jsonString(data["browser_info"]),
		Timezone:       utils.SanitizeInput(data["timezone"].(string), 50),
		Plugins:        jsonString(data["plugins"]),
		DoNotTrack:     utils.SanitizeInput(data["doNotTrack"].(string), 10),
		Keystrokes:     jsonString(data["keystrokes"]),
		FocusEvents:    jsonString(data["focus_events"]),
	}
	if models.DB.Create(&attempt).Error != nil {
		return false
	}
	return true
}

func logRegistrationAttempt(data map[string]interface{}, ip string) bool {
	password := data["password"].(string)
	attempt := models.RegistrationAttempt{
		SessionID:            utils.SanitizeInput(data["session_id"].(string), 100),
		AttemptNumber:        int(data["attempt_number"].(float64)),
		Fullname:             utils.SanitizeInput(data["fullname"].(string), 255),
		Email:                utils.SanitizeInput(data["email"].(string), 255),
		Username:             utils.SanitizeInput(data["username"].(string), 255),
		PasswordHash:         password,
		TermsAccepted:        data["terms_accepted"].(bool),
		NewsletterSubscribed: data["newsletter_subscribed"].(bool),
		IPAddress:            ip,
		UserAgent:            utils.SanitizeInput(data["user_agent"].(string), 500),
		Referrer:             utils.SanitizeInput(data["referrer"].(string), 500),
		MouseMovements:       jsonString(data["mouse_movements"]),
		FormFillTime:         int(data["form_fill_time"].(float64)),
		ScreenInfo:           jsonString(data["screen_info"]),
		BrowserInfo:          jsonString(data["browser_info"]),
		Timezone:             utils.SanitizeInput(data["timezone"].(string), 50),
		Plugins:              jsonString(data["plugins"]),
		DoNotTrack:           utils.SanitizeInput(data["doNotTrack"].(string), 10),
		Keystrokes:           jsonString(data["keystrokes"]),
		FocusEvents:          jsonString(data["focus_events"]),
	}
	if models.DB.Create(&attempt).Error != nil {
		return false
	}
	return true
}

func logGeneralActivity(sessionID, activityType string, data map[string]interface{}, ip string) bool {
	dataJSON, _ := json.Marshal(data)
	activity := models.ActivityLog{
		SessionID:    sessionID,
		ActivityType: activityType,
		Data:         string(dataJSON),
		IPAddress:    ip,
	}
	return models.DB.Create(&activity).Error == nil
}

func logFingerprint(sessionID string, data map[string]interface{}, ip string) bool {
	dataJSON, _ := json.Marshal(data)
	fp := models.Fingerprint{
		SessionID: sessionID,
		Data:      string(dataJSON),
	}
	return models.DB.Create(&fp).Error == nil
}

func jsonString(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

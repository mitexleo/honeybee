package models

import (
	"log"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

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

func InitDatabase(dbPath string) {
	if dbPath == "" {
		dbPath = "data/honeypot.db"
	}
	dsn := dbPath + "?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=1000&_temp_store=MEMORY"
	var err error
	DB, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatal("Database init failed: ", err)
	}

	// AutoMigrate models
	err = DB.AutoMigrate(&Session{}, &LoginAttempt{}, &RegistrationAttempt{}, &ActivityLog{}, &Fingerprint{})
	if err != nil {
		log.Fatal("Migration failed: ", err)
	}

	// Create indexes for better performance
	sqlDB, _ := DB.DB()
	sqlDB.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip_address);")
	sqlDB.Exec("CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address);")
	sqlDB.Exec("CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(timestamp);")
	sqlDB.Exec("CREATE INDEX IF NOT EXISTS idx_activity_log_time ON activity_log(timestamp);")
}

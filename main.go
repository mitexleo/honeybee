package main

import (
	"context"
	"fmt"
	"honeybee/config"
	"honeybee/middleware"
	"honeybee/models"
	"honeybee/routes"
	"honeybee/utils"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	// Ensure data directory exists
	dataDir := filepath.Dir(config.GetDatabasePath())
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database and models with config
	models.InitDatabase(cfg.Database.Path)

	// Initialize geolocation database with config
	utils.InitGeoDB(cfg.GeoIP.Path)

	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	r := gin.New() // No default middleware, add custom
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// Middleware
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.SecurityHeaders())

	routes.SetupRoutes(r)

	// Create HTTP server
	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler: r,
	}

	// Channel to listen for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		log.Printf("Starting Honeypot Server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

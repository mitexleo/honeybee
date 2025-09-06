// routes/routes.go
package routes

import (
	"honeybee/controllers"
	"honeybee/middleware"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	// Public routes for HTML pages
	r.GET("/", controllers.Index)
	r.GET("/register.html", controllers.Register)

	// Static files for frontend (directly served at root paths as expected by HTML)
	r.StaticFile("/styles.css", "./frontend/styles.css")
	r.StaticFile("/script.js", "./frontend/script.js")
	r.StaticFile("/register.js", "./frontend/register.js")
	r.StaticFile("/dashboard.html", "./frontend/dashboard.html")

	// Conditional serving for optional files
	r.GET("/nextcloud.webp", func(c *gin.Context) {
		if _, err := os.Stat("./frontend/nextcloud.webp"); os.IsNotExist(err) {
			c.Data(http.StatusOK, "image/webp", []byte{}) // Placeholder or 404
			return
		}
		c.File("./frontend/nextcloud.webp")
	})

	// API routes
	r.POST("/api/login", controllers.Login)
	r.POST("/api/honeypot/log", controllers.LogHoneypotActivity)
	r.GET("/api/client-ip", controllers.GetClientIP)

	// Admin routes
	r.GET("/admin/dashboard", middleware.RequireJWTAuth(), controllers.GetDashboardData)
	r.GET("/admin/export/csv", middleware.RequireJWTAuth(), controllers.ExportCSV)
	r.GET("/admin/export/json", middleware.RequireJWTAuth(), controllers.ExportJSON)
	r.GET("/admin/metrics", middleware.RequireJWTAuth(), controllers.Metrics)
	r.GET("/admin", middleware.RequireJWTAuth(), controllers.AdminDashboard)

	// Health check
	r.GET("/health", controllers.HealthCheck)

	// Fallback static serving for any other frontend files
	r.Static("/frontend", "./frontend")
}

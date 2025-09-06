package routes

import (
	"honeybee/controllers"
	"honeybee/middleware"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	// Public routes
	r.GET("/", controllers.Index)
	r.GET("/register.html", controllers.Register)
	r.GET("/health", controllers.HealthCheck)
	r.POST("/api/login", controllers.Login)
	r.POST("/api/honeypot/log", controllers.LogHoneypotActivity)
	r.GET("/api/client-ip", controllers.GetClientIP)

	// Admin routes
	r.GET("/admin/dashboard", middleware.RequireJWTAuth(), controllers.GetDashboardData)
	r.GET("/admin/export/csv", middleware.RequireJWTAuth(), controllers.ExportCSV)
	r.GET("/admin/export/json", middleware.RequireJWTAuth(), controllers.ExportJSON)
	r.GET("/admin/metrics", middleware.RequireJWTAuth(), controllers.Metrics)
	r.GET("/admin", middleware.RequireJWTAuth(), controllers.AdminDashboard)

	// Serve static files
	r.Static("/frontend", "./frontend")
}

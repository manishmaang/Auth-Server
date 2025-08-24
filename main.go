package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/manishmaang/auth-server/config"
	"github.com/manishmaang/auth-server/routes"
)

func main() {
	router := gin.Default()
	router.GET("/hello", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "hello world!! from golang server",
		})
	})
	routes.AllRoutes(router)
	router.Run(":3000")
}

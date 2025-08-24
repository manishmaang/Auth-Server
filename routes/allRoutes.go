package routes

import "github.com/gin-gonic/gin"

func AllRoutes(router *gin.Engine) {
	UserRoutes(router)
	LoginRoutes(router)
}

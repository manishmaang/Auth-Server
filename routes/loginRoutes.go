package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/manishmaang/auth-server/controllers"
)

func LoginRoutes(router *gin.Engine){
	router.POST("/login", controllers.Login);
}
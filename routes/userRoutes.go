package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/manishmaang/auth-server/controllers"
)

func UserRoutes(router *gin.Engine){
	router.POST("/user/register", controllers.RegisterUser);
}
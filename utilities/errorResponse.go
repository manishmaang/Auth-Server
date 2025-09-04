package utilities

import (
	"github.com/gin-gonic/gin"
)

func SendError(ctx *gin.Context, code int, msg string) {
	ctx.JSON(code, gin.H{
		"success": false,
		"error":   msg,
	})
}

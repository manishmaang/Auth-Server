package controllers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/manishmaang/auth-server/config"
	"golang.org/x/crypto/bcrypt"
)

func HashString(ss string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(ss), bcrypt.DefaultCost) // returns and accepts byte as string are immutable in golang
	if err != nil {
		log.Fatal("Error while generating the hash, error is : ", err.Error())
		return "", err
	}
	return string(bytes), nil
}

func RegisterUser(ctx *gin.Context) {
	var req_body User
	if err := ctx.BindJSON(&req_body); err != nil {
		log.Println("Error while retrieveing the payload error is : ", err.Error())
		ctx.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	var user_exists bool
	query := "select exists (select 1 from auth_users where email = $1)"
	if err := config.DB.Raw(query, req_body.Email).Scan(&user_exists).Error; err != nil {
		log.Println("Error while checking user exists or not, error is ", err.Error())
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	hashed_password, err := HashString(req_body.Password)
	if err != nil {
		log.Println("Error while hashing the password, error is : ", err.Error())
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	} else if user_exists {
		ctx.JSON(http.StatusConflict, gin.H{
			"success": false,
			"error":   "User already exists",
		})
		return
	}

	query = "insert into auth_users (email, hashed_password) values ($1, $2) returning id"

	var user_id uint
	if err := config.DB.Raw(query, req_body.Email, hashed_password).Scan(&user_id).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{
		"success": true,
		"data": gin.H{
			"id":    user_id,
			"email": req_body.Email,
		},
	})

}

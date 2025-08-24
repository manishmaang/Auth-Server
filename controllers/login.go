package controllers

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/manishmaang/auth-server/config"
	"github.com/manishmaang/auth-server/models"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mail.v2"
)

func ComparePasswords(hashed_password string, plain_password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashed_password), []byte(plain_password))
	if err != nil {
		return false, err
	}

	return true, nil
}

// NOTE :
// RAW is used for select queries and it won't run for update delete or insert
// But it does run in users.go for insert because =>  Raw is designed for SELECT queries, but in PostgreSQL, INSERT ... RETURNING acts like a SELECT by returning rows.
// GORM’s Raw can scan the returned value (e.g., id) into a variable, just like a SELECT. 
func Login(ctx *gin.Context) {
	var req_body LoginPayload

	if err := ctx.BindJSON(&req_body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	var db_user models.User
	query := "select * from auth_users where email = $1"

	if err := config.DB.Raw(query, req_body.UserDetails.Email).Scan(&db_user).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	} else if db_user.Email == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "",
		})
		return
	}

	same_password, err := ComparePasswords(db_user.HashedPassword, req_body.UserDetails.Password)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   err.Error(),
			"success": false,
		})
		return
	} else if !same_password {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "Invalid Credentials",
		})
		return
	}

	if db_user.MFA { // send the otp to the mail and temp code here
		temp_code := generateTempCode()
		otp := generateOTP()

		query = "update auth_users set temp_code = $1, otp_secret = $2 where email = $3"
		err := config.DB.Exec(query, temp_code, otp, req_body.UserDetails.Email).Error
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   err.Error(),
			})
			return
		}

		// send otp to the user
		subject := fmt.Sprintf("OTP FOR %s's Verification", req_body.ApplicationName)
		message := fmt.Sprintf("Your OTP to login in the %s is %s", req_body.ApplicationName, otp)
		m := mail.NewMessage()
		m.SetHeader("From", config.EnvValue("EMAIL"))
		m.SetHeader("To", req_body.UserDetails.Email)
		m.SetHeader("Subject", subject)
		m.SetBody("text/plain", message)

		d := mail.NewDialer("smtp.gmail.com", 587, config.EnvValue("EMAIL"), config.EnvValue("EMAIL_PASSWORD"))

		if err := d.DialAndSend(m); err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "Failed to send email: " + err.Error(),
			})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{
			"success":       true,
			"mfa":           true,
			"temp_code":     temp_code,
			"access_token":  nil,
			"refresh_token": nil,
		})
	} else { // normal login
		access_token, refresh_token, err := generateToken(req_body)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   err.Error(),
			})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{
			"success":       true,
			"mfa":           false,
			"temp_code":     nil,
			"access_token":  access_token,
			"refresh_token": refresh_token,
		})
	}
}

// HELPER FUNCTIONS
func generateToken(user_details LoginPayload) (string, string, error) {
	access_claims := jwt.MapClaims{}
	refresh_claims := jwt.MapClaims{}

	now := time.Now().Unix()
	access_expiry := time.Now().Add(30 * time.Minute).Unix()
	refresh_expiry := time.Now().Add(60 * time.Minute).Unix()

	for key, value := range user_details.RefreshPayload {
		access_claims[key] = value
	}

	for key, value := range user_details.AccessPayload {
		refresh_claims[key] = value
	}

	access_claims["iat"] = now
	refresh_claims["iat"] = now
	access_claims["exp"] = access_expiry
	refresh_claims["exp"] = refresh_expiry

	access_token := jwt.NewWithClaims(jwt.SigningMethodHS256, access_claims)
	access_string, err := access_token.SignedString([]byte(config.EnvValue("JWT_SECRET"))) // signing the token with jwt secret
	if err != nil {
		return "", "", err
	}

	refresh_token := jwt.NewWithClaims(jwt.SigningMethodHS256, refresh_claims)
	refresh_string, err := refresh_token.SignedString([]byte(config.EnvValue("REFRESH_SECRET")))
	if err != nil {
		return "", "", err
	}

	return access_string, refresh_string, nil
}

func generateTempCode() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 32) // 32 character long code
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func generateOTP() string {
	// Seed the random generator (important for different results each run)
	rand.Seed(time.Now().UnixNano())

	// Generate number between 1000 and 9999
	otp_string := fmt.Sprintf("%d", rand.Intn(9000)+1000)
	return otp_string
}

package controllers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/manishmaang/auth-server/config"
	"github.com/manishmaang/auth-server/models"
	"github.com/manishmaang/auth-server/utilities"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mail.v2"
)

// NOTE :
// RAW is used for select queries and it won't run for update delete or insert
// But it does run in users.go for insert because =>  Raw is designed for SELECT queries, but in PostgreSQL, INSERT ... RETURNING acts like a SELECT by returning rows.
// GORM’s Raw can scan the returned value (e.g., id) into a variable, just like a SELECT.
func Login(ctx *gin.Context) {
	// start := time.Now()
	var req_body LoginPayload
	if err := ctx.ShouldBindJSON(&req_body); err != nil {
		utilities.SendError(ctx, http.StatusBadRequest, err.Error())
		return
	}

	if req_body.Password == "" && req_body.TempCode == "" {
		utilities.SendError(ctx, http.StatusBadRequest, "Either temp_code or password must be provided")
		return
	}

	// fmt.Println("Payload Comparison : ", time.Since(start))
	if req_body.Password != "" {
		handlePasswordLogin(ctx, req_body)
	} else {
		handleTempCodeLogin(ctx, req_body)
	}
}

func VerifyOtp(ctx *gin.Context) {
	type Payload struct {
		Otp      string `json:"otp" binding:"required"`
		TempCode string `json:"temp_code" binding:"required"`
	}

	var req_body Payload
	if err := ctx.BindJSON(&req_body); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	token_claims, err := utilities.ValidateSymmetricTokens(req_body.TempCode, "MFA_SECRET")
	if err != nil {
		utilities.SendError(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	if token_expired := utilities.CheckExpiry(token_claims); token_expired {
		utilities.SendError(ctx, http.StatusBadRequest, "Invalid Token")
		return
	}

	email, ok := token_claims["email"].(string)
	if !ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "Invalid temp code",
		})
		return
	}

	var db_user models.User
	query := "select otp_secret from auth_users where email = $1"
	if err := config.DB.Raw(query, email).Scan(&db_user).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	if db_user.OTPSecret != req_body.Otp {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "Invalid Credentials",
		})
		return
	}

	user_code, err := utilities.GenerateMfaToken(email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// don't need to save it the jwt token, i can validate the token to get the info.
	// query = "update auth_users set user_code = $1 where id = $2"
	// result := config.DB.Exec(query, user_code, db_user.ID)
	// if result.Error != nil {
	// 	ctx.JSON(http.StatusInternalServerError, gin.H{
	// 		"success": false,
	// 		"error":   result.Error.Error(),
	// 	})
	// 	return
	// }

	ctx.JSON(http.StatusOK, gin.H{
		"success":   true,
		"user_code": user_code,
	})
}

// helper functions
func handlePasswordLogin(ctx *gin.Context, req_body LoginPayload) {
	start := time.Now()
	db_user, err := fetchUserByEmail(req_body.Email)
	fmt.Println("User Fetching : ", time.Since(start))
	if err != nil {
		utilities.SendError(ctx, http.StatusUnauthorized, err.Error())
		return
	} else if db_user.HashedPassword == "" {
		utilities.SendError(ctx, http.StatusForbidden, "You must set up your password before logging in.")
		return
	}

	match, err := compareHashPassword(db_user.HashedPassword, req_body.Password)
	fmt.Println("Password Comparison : ", time.Since(start))
	if err != nil {
		utilities.SendError(ctx, http.StatusInternalServerError, err.Error())
		return
	} else if !match {
		utilities.SendError(ctx, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if db_user.MFA {
		handleMfaFlow(ctx, db_user.Email, req_body.ApplicationName)
		return
	}

	generateTokensAndRespond(ctx, req_body, false, nil)
	// fmt.Println("Response Sending : ", time.Since(start))
}

func handleTempCodeLogin(ctx *gin.Context, req_body LoginPayload) {
	claims, err := utilities.ValidateSymmetricTokens(req_body.TempCode, "MFA_SECRET")
	if err != nil {
		utilities.SendError(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	if utilities.CheckExpiry(claims) {
		utilities.SendError(ctx, http.StatusBadRequest, "Temp Code is not valid")
		return
	}

	generateTokensAndRespond(ctx, req_body, nil, nil)
}

func compareHashPassword(hashed_password string, plain_password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashed_password), []byte(plain_password))
	if err != nil {
		return false, err
	}

	return true, nil
}

func fetchUserByEmail(email string) (*models.User, error) {
	var user models.User
	query := "select * from auth_users where email = ?"
	result := config.DB.Raw(query, email).Scan(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	if user.Email == "" {
		return nil, fmt.Errorf("user not found")
	}
	return &user, nil
}

func handleMfaFlow(ctx *gin.Context, email string, appName string) {
	start := time.Now()
	temp_code, err := utilities.GenerateMfaToken(email)
	fmt.Println("temp code generation : ", time.Since(start))
	otp := utilities.GenerateOtp()
	fmt.Println("otp generation : ", time.Since(start))
	if err != nil {
		utilities.SendError(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	query := "update auth_users set temp_code = ?, otp_secret = ? where email = ?"
	if err := config.DB.Exec(query, temp_code, otp, email).Error; err != nil {
		utilities.SendError(ctx, http.StatusInternalServerError, err.Error())
		return
	}
	fmt.Println("db updation : ", time.Since(start))

	subject := fmt.Sprintf("OTP FOR %s's Verification", appName)
	message := fmt.Sprintf("Your OTP to login in the %s is %s", appName, otp)

	go func() {
		m := mail.NewMessage()
		m.SetHeader("From", config.EnvValue("EMAIL"))
		m.SetHeader("To", email)
		m.SetHeader("Subject", subject)
		m.SetBody("text/plain", message)

		d := mail.NewDialer("smtp.gmail.com", 587, config.EnvValue("EMAIL"), config.EnvValue("EMAIL_PASSWORD"))
		if err := d.DialAndSend(m); err != nil {
			// utilities.SendError(ctx, http.StatusInternalServerError, err.Error())
			fmt.Println("Error sending email:", err.Error())
			return
		}
	}()
	fmt.Println("email sending : ", time.Since(start))

	ctx.JSON(http.StatusOK, gin.H{
		"success":       true,
		"mfa":           true,
		"temp_code":     temp_code,
		"access_token":  nil,
		"refresh_token": nil,
	})
}

func generateTokensAndRespond(ctx *gin.Context, req_body LoginPayload, mfa any, tempCode any) {
	access, refresh, err := generateTokens(req_body.AccessPayload, req_body.RefreshPayload)
	if err != nil {
		utilities.SendError(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"success":       true,
		"mfa":           mfa,
		"temp_code":     tempCode,
		"access_token":  access,
		"refresh_token": refresh,
	})
}

func generateTokens(access_payload map[string]any, refresh_payload map[string]any) (string, string, error) {
	access_token, err := utilities.GenerateAsymettricToken(access_payload)
	if err != nil {
		return "", "", err
	}

	refresh_token, err := utilities.GenerateRefreshToken(refresh_payload)
	if err != nil {
		return "", "", err
	}

	return access_token, refresh_token, nil
}

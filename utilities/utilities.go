package utilities

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/manishmaang/auth-server/config"
)

func GenerateAsymettricToken(payload map[string]any) (string, error) {
	file_data, err := os.ReadFile("../private.pem")
	if err != nil {
		// panic(err) // stops the program and shows the error
		return "", err
	}

	private_key, err := jwt.ParseRSAPrivateKeyFromPEM(file_data)
	//It takes your raw .pem file (which has -----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----)
	// Parses it into a usable RSA private key object (*rsa.PrivateKey) in Go.
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	expiry := time.Now().Add(60 * time.Minute).Unix()
	claims := jwt.MapClaims{}
	for key, value := range payload {
		claims[key] = value
	}
	claims["iat"] = now
	claims["exp"] = expiry

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "my-key-1"

	// signing the token
	signed_token, err := token.SignedString(private_key)
	if err != nil {
		return "", err
	}
	return signed_token, nil
}

func GenerateRefreshToken(payload map[string]any) (string, error) {
	claims := jwt.MapClaims{}
	for key, value := range payload {
		claims[key] = value
	}

	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(7 * 60 * time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed_token, err := token.SignedString([]byte(config.EnvValue("REFRESH_SECRET")))
	if err != nil {
		return "", nil
	}

	return signed_token, nil
}


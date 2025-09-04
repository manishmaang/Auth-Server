package utilities

import (
	"fmt"
	"os"
	"time"
	"math/rand"
	"github.com/golang-jwt/jwt/v5"
	"github.com/manishmaang/auth-server/config"
)

func GenerateAsymettricToken(payload map[string]any) (string, error) {
	file_data, err := os.ReadFile("private.pem")
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

func GenerateMfaToken(email string) (string, error) {
	claims := jwt.MapClaims{}
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(5 * 60 * time.Minute)
	claims["email"] = email
	mfa_token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed_token, err := mfa_token.SignedString([]byte(config.EnvValue("MFA_SECRET")))
	if err != nil {
		return "", err
	}
	return signed_token, nil
}

func ValidateSymmetricTokens(tokenString string, secretString string) (map[string]any, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return config.EnvValue(secretString), nil
	})

	claims, ok := token.Claims.(jwt.MapClaims)
	if err != nil {
		return nil, err
	} else if !token.Valid || !ok {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func ValidateAsymmetricTokens(tokenString string) (map[string]any, error) {
	// Read the public key
	file_data, err := os.ReadFile("public.pem")
	if err != nil {
		return nil, err
	}

	public_key, err := jwt.ParseRSAPublicKeyFromPEM(file_data)
	if err != nil {
		return nil, err
	}

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return public_key, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !token.Valid || !ok {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func CheckExpiry(claims map[string]any) bool {
	// Check expiry
	// claims["exp"].(float64) => we are expecting claims["exp"] has a value of type float (this is called type assertion)
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if time.Now().After(expTime) {
			fmt.Println("token has expired")
			return true
		}
	} else {
		fmt.Println("Invalid exp claims")
		return true
	}
	return false
}

func GenerateOtp() string {
	// Seed the random generator (important for different results each run)
	rand.Seed(time.Now().UnixNano())

	// Generate number between 1000 and 9999
	otp_string := fmt.Sprintf("%d", rand.Intn(9000)+1000)
	return otp_string
}

// NOTE :
// During jwt.Parse (or ParseWithClaims):
// The token string is split into header.payload.signature.
// The header is parsed → determines which signing algorithm (e.g., HS256).
// The payload (claims) is decoded into MapClaims or RegisteredClaims.
// The signature is checked:
// The library calls your keyFunc (the callback you wrote returning jwtSecret).
// It verifies that HMAC(payload, secret) == signature (or RSA/ECDSA equivalent).
// If signature check passes and parsing was successful → token.Valid = true.
// If signature fails or token is malformed → token.Valid = false.

// Abount JWT JSON ENCODING
// When the JWT library encodes this to JSON, numbers in JSON don’t have an int64 type — JSON only has a single “number” type.
// When Go’s JSON decoder (encoding/json) parses that number back, it defaults to decoding all JSON numbers into float64.
// That’s why, even though we set it as int64, when we read it back from the claims map, it comes out as float64.

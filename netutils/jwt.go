package netutils

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type JwtPayload map[string]interface{}

type Claims struct {
	Payload JwtPayload `json:"payload"`
	jwt.RegisteredClaims
}

func GenerateJWTToken(payload JwtPayload, key string) (*string, error) {
	encryptedPayload, err := EncryptPayload(payload, key)
	if err != nil {
		return nil, errors.New("failed to encrypt payload")
	}
	fmt.Printf("Encrypted payload: %v\n", encryptedPayload)
	claims := &Claims{
		Payload: encryptedPayload,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    os.Getenv("APP_NAME"),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return nil, errors.New("invalid auth token")
	}
	return &signedToken, nil
}

func (c *Claims) GetPayload(key string) (map[string]interface{}, error) {
	decryptedPayload, err := DecryptPayload(c.Payload, key)
	if err != nil {
		return nil, errors.New("failed to decrypt payload")
	}
	return decryptedPayload, nil
}

func DecryptJWTToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			err := fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			return nil, err
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	if time.Now().After(claims.ExpiresAt.Time) {
		return nil, errors.New("expired token")
	}

	return claims, nil
}

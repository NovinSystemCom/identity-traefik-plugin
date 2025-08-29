package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Example demonstrating how the Identity Plugin works with different environments
func main() {
	secretKey := "YourSuperSecretKeyThatIsAtLeast32CharactersLong"

	// Create JWTs for testing
	fmt.Println("=== JWT Token Examples ===")

	// JWT without enforce_security_stamp (will pass through)
	tokenWithoutStamp := createJWT(secretKey, jwt.MapClaims{
		"sub":  "user123",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	fmt.Printf("Token without security stamp:\n%s\n\n", tokenWithoutStamp)

	// JWT with enforce_security_stamp = false (will pass through)
	tokenStampFalse := createJWT(secretKey, jwt.MapClaims{
		"sub":                    "user123",
		"name":                   "John Doe",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": false,
	})
	fmt.Printf("Token with security stamp = false:\n%s\n\n", tokenStampFalse)

	// JWT with enforce_security_stamp = true (will validate with identity service)
	tokenStampTrue := createJWT(secretKey, jwt.MapClaims{
		"sub":                    "user123",
		"name":                   "John Doe",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})
	fmt.Printf("Token with security stamp = true:\n%s\n\n", tokenStampTrue)

	fmt.Println("=== Environment Routing Examples ===")
	fmt.Println("Request to api.novin-system.com → Production Identity Service")
	fmt.Println("Request to api.novin-stage.com → Staging Identity Service")
	fmt.Println("Request to unknown.domain.com → Default Identity Service")

	fmt.Println("\n=== Sample Configuration ===")
	config := map[string]interface{}{
		"jwtSecretKey": "{{ env \"JWT_SECRET_KEY\" }}",
		"environmentServices": map[string]string{
			"api.novin-system.com": "https://api.identity.novin-system.com/api/v1/auth/validate-token",
			"api.novin-stage.com":  "https://api.identity.novin-stage.com/api/v1/auth/validate-token",
		},
		"defaultIdentityServiceURL": "https://api.identity.novin-stage.com/api/v1/auth/validate-token",
		"productionDomains":         []string{"api.novin-system.com"},
		"stagingDomains":            []string{"api.novin-stage.com"},
	}

	configJSON, _ := json.MarshalIndent(config, "", "  ")
	fmt.Printf("%s\n", configJSON)

	fmt.Println("\n=== Test Commands ===")
	fmt.Printf("# Test production environment:\n")
	fmt.Printf("curl -H \"Host: api.novin-system.com\" -H \"Authorization: Bearer %s\" http://localhost/api/test\n\n", tokenStampTrue)

	fmt.Printf("# Test staging environment:\n")
	fmt.Printf("curl -H \"Host: api.novin-stage.com\" -H \"Authorization: Bearer %s\" http://localhost/api/test\n\n", tokenStampTrue)

	fmt.Printf("# Test without token (should pass through):\n")
	fmt.Printf("curl -H \"Host: api.novin-system.com\" http://localhost/api/public\n")
}

func createJWT(secretKey string, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "Error creating token: " + err.Error()
	}
	return tokenString
}

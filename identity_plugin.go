package traefik_identity_plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config the plugin configuration.
type Config struct {
	JWTSecretKey              string            `json:"jwtSecretKey,omitempty"`
	IdentityServiceURL        string            `json:"identityServiceURL,omitempty"`        // Deprecated: use EnvironmentServices instead
	EnvironmentServices       map[string]string `json:"environmentServices,omitempty"`       // Map of host patterns to identity service URLs
	DefaultIdentityServiceURL string            `json:"defaultIdentityServiceURL,omitempty"` // Fallback URL
	ProductionDomains         []string          `json:"productionDomains,omitempty"`         // List of production domains
	StagingDomains            []string          `json:"stagingDomains,omitempty"`            // List of staging domains
	Timeout                   time.Duration     `json:"timeout,omitempty"`                   // HTTP client timeout
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		JWTSecretKey: "YourSuperSecretKeyThatIsAtLeast32CharactersLong",
		EnvironmentServices: map[string]string{
			"api.novin-system.com": "https://api.identity.novin-system.com/api/v1/auth/validate-token",
			"api.novin-stage.com":  "https://api.identity.novin-stage.com/api/v1/auth/validate-token",
		},
		DefaultIdentityServiceURL: "https://api.identity.novin-stage.com/api/v1/auth/validate-token",
		ProductionDomains:         []string{"api.novin-system.com"},
		StagingDomains:            []string{"api.novin-stage.com"},
		Timeout:                   10 * time.Second,
	}
}

// IdentityPlugin a plugin.
type IdentityPlugin struct {
	next   http.Handler
	name   string
	config *Config
	client *http.Client
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.JWTSecretKey) == 0 {
		return nil, fmt.Errorf("JWT secret key cannot be empty")
	}

	// Backward compatibility: if IdentityServiceURL is set but EnvironmentServices is empty
	if len(config.IdentityServiceURL) > 0 && len(config.EnvironmentServices) == 0 {
		config.DefaultIdentityServiceURL = config.IdentityServiceURL
	}

	// Validate that we have at least one way to determine the identity service URL
	if len(config.EnvironmentServices) == 0 && len(config.DefaultIdentityServiceURL) == 0 {
		return nil, fmt.Errorf("either environmentServices or defaultIdentityServiceURL must be configured")
	}

	return &IdentityPlugin{
		next:   next,
		name:   name,
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}, nil
}

func (a *IdentityPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")

	// If Authorization header is empty, pass the request to the next handler
	if authHeader == "" {
		a.next.ServeHTTP(rw, req)
		return
	}

	// Extract token from Authorization header
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		// Authorization header doesn't start with "Bearer "
		http.Error(rw, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	// Parse and validate JWT
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.config.JWTSecretKey), nil
	})

	if err != nil || !parsedToken.Valid {
		http.Error(rw, "Invalid JWT token", http.StatusUnauthorized)
		return
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(rw, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	// Check for enforce_security_stamp claim
	enforceSecurityStampRaw, exists := claims["enforce_security_stamp"]
	if !exists {
		// If claim doesn't exist, pass the request to the next handler
		http.Error(rw, "enforce_security_stamp claim not found", http.StatusUnauthorized)
		return
	}

	// Validate that enforce_security_stamp is a boolean
	enforceSecurityStamp, ok := enforceSecurityStampRaw.(bool)
	if !ok {
		// Invalid type (not boolean), return 401
		http.Error(rw, "Invalid enforce_security_stamp claim type", http.StatusUnauthorized)
		return
	}

	// If enforce_security_stamp is false, pass the request to the next handler
	if !enforceSecurityStamp {
		a.next.ServeHTTP(rw, req)
		return
	}

	// If enforce_security_stamp is true, validate token with identity service
	valid, err := a.validateTokenWithIdentityService(req, token)
	if err != nil {
		http.Error(rw, "Error validating token with identity service", http.StatusInternalServerError)
		return
	}

	if !valid {
		http.Error(rw, "Token validation failed", http.StatusUnauthorized)
		return
	}

	// Token is valid, pass the request to the next handler
	a.next.ServeHTTP(rw, req)
}

// IdentityServiceResponse represents the response from the identity service
type IdentityServiceResponse struct {
	Data struct {
		IsValid   bool     `json:"isValid"`
		UserID    int      `json:"userId"`
		Username  string   `json:"username"`
		FullName  *string  `json:"fullName"`
		Roles     []string `json:"roles"`
		ExpiresAt string   `json:"expiresAt"`
	} `json:"data"`
	Message          *string                `json:"message"`
	ValidationErrors map[string]interface{} `json:"validationErrors"`
	IsSuccess        bool                   `json:"isSuccess"`
}

// validateTokenWithIdentityService validates the token with the identity microservice
func (a *IdentityPlugin) validateTokenWithIdentityService(req *http.Request, token string) (bool, error) {
	identityServiceURL := a.getIdentityServiceURL(req)

	url := fmt.Sprintf("%s?accessToken=%s", identityServiceURL, token)

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("accept", "*/*")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("identity service returned non-200 status: %d", resp.StatusCode)
	}

	var identityResp IdentityServiceResponse
	if err := json.Unmarshal(body, &identityResp); err != nil {
		return false, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	return identityResp.Data.IsValid, nil
}

// getIdentityServiceURL determines the appropriate identity service URL based on the request
func (a *IdentityPlugin) getIdentityServiceURL(req *http.Request) string {
	requestHost := req.Host

	if len(a.config.EnvironmentServices) > 0 {
		// Check for exact match first
		if serviceURL, exists := a.config.EnvironmentServices[requestHost]; exists {
			return serviceURL
		}

		// Check for pattern matches (e.g., wildcards or subdomain patterns)
		for hostPattern, serviceURL := range a.config.EnvironmentServices {
			if a.matchesHostPattern(requestHost, hostPattern) {
				return serviceURL
			}
		}
	}

	// If no direct mapping found, check if it's a production domain
	for _, prodDomain := range a.config.ProductionDomains {
		if a.matchesHostPattern(requestHost, prodDomain) {
			// Try to find production service URL in EnvironmentServices
			if len(a.config.EnvironmentServices) > 0 {
				for pattern, serviceURL := range a.config.EnvironmentServices {
					if a.matchesHostPattern(prodDomain, pattern) {
						return serviceURL
					}
				}
			}
			// Fallback to constructing production URL
			return strings.Replace(a.config.DefaultIdentityServiceURL, "novin-stage", "novin-system", 1)
		}
	}

	// If no specific mapping found, return the default
	return a.config.DefaultIdentityServiceURL
}

// matchesHostPattern checks if a host matches a pattern (supports simple wildcard matching)
func (a *IdentityPlugin) matchesHostPattern(host, pattern string) bool {
	if host == pattern {
		return true
	}

	// Support for wildcard patterns like *.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return strings.HasSuffix(host, suffix)
	}

	// Support for prefix patterns like api.*
	if strings.HasSuffix(pattern, ".*") {
		prefix := pattern[:len(pattern)-2]
		return strings.HasPrefix(host, prefix)
	}

	return false
}

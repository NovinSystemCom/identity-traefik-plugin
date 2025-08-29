package traefik_identity_plugin_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	plugin "git.novin-tools.com/devops/traefik-identity-plugin"
	"github.com/golang-jwt/jwt/v5"
)

func TestIdentityPlugin_EmptyAuthorizationHeader(t *testing.T) {
	cfg := plugin.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusOK)
}

func TestIdentityPlugin_ValidJWTWithoutEnforceSecurityStamp(t *testing.T) {
	cfg := plugin.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid JWT without enforce_security_stamp claim
	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusUnauthorized)
}

func TestIdentityPlugin_ValidJWTWithEnforceSecurityStampFalse(t *testing.T) {
	cfg := plugin.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid JWT with enforce_security_stamp = false
	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "John Doe",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": false,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusOK)
}

func TestIdentityPlugin_InvalidJWT(t *testing.T) {
	cfg := plugin.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusUnauthorized)
}

func TestIdentityPlugin_EnforceSecurityStampInvalidType(t *testing.T) {
	cfg := plugin.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	// Create a JWT with enforce_security_stamp as string (invalid type)
	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "John Doe",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": "true", // String instead of boolean
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusUnauthorized)
}

func TestIdentityPlugin_EnforceSecurityStampTrueWithValidResponse(t *testing.T) {
	// Create mock identity service
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"isValid":   true,
				"userId":    2,
				"username":  "2",
				"fullName":  nil,
				"roles":     []string{"customer.admin.super"},
				"expiresAt": "2025-08-29T16:44:08+00:00",
			},
			"message":          nil,
			"validationErrors": map[string]interface{}{},
			"isSuccess":        true,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	cfg := plugin.CreateConfig()
	cfg.DefaultIdentityServiceURL = mockServer.URL

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	// Create a JWT with enforce_security_stamp = true
	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "John Doe",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusOK)
}

func TestIdentityPlugin_EnforceSecurityStampTrueWithInvalidResponse(t *testing.T) {
	// Create mock identity service that returns invalid token
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"isValid":   false,
				"userId":    0,
				"username":  "",
				"fullName":  nil,
				"roles":     []string{},
				"expiresAt": "",
			},
			"message":          nil,
			"validationErrors": map[string]interface{}{},
			"isSuccess":        false,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	cfg := plugin.CreateConfig()
	cfg.DefaultIdentityServiceURL = mockServer.URL

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	// Create a JWT with enforce_security_stamp = true
	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "John Doe",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusUnauthorized)
}

func createTestJWT(t *testing.T, secretKey string, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		t.Fatal(err)
	}
	return tokenString
}

func assertStatus(t *testing.T, res *http.Response, expected int) {
	t.Helper()
	if res.StatusCode != expected {
		t.Errorf("invalid status: got %d, expected %d", res.StatusCode, expected)
	}
}

func TestIdentityPlugin_EnvironmentAwareProduction(t *testing.T) {
	// Create mock production identity service
	prodMockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"isValid":   true,
				"userId":    2,
				"username":  "prod-user",
				"fullName":  "Production User",
				"roles":     []string{"admin"},
				"expiresAt": "2025-08-29T16:44:08+00:00",
			},
			"message":          nil,
			"validationErrors": map[string]interface{}{},
			"isSuccess":        true,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer prodMockServer.Close()

	cfg := plugin.CreateConfig()
	cfg.EnvironmentServices = map[string]string{
		"api.novin-system.com": prodMockServer.URL,
		"api.novin-stage.com":  "http://staging-service",
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	// Create a JWT with enforce_security_stamp = true
	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "John Doe",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://api.novin-system.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.novin-system.com" // Set the host to production
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusOK)
}

func TestIdentityPlugin_EnvironmentAwareStaging(t *testing.T) {
	// Create mock staging identity service
	stagingMockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"isValid":   true,
				"userId":    3,
				"username":  "staging-user",
				"fullName":  "Staging User",
				"roles":     []string{"tester"},
				"expiresAt": "2025-08-29T16:44:08+00:00",
			},
			"message":          nil,
			"validationErrors": map[string]interface{}{},
			"isSuccess":        true,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer stagingMockServer.Close()

	cfg := plugin.CreateConfig()
	cfg.EnvironmentServices = map[string]string{
		"api.novin-system.com": "http://prod-service",
		"api.novin-stage.com":  stagingMockServer.URL,
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	// Create a JWT with enforce_security_stamp = true
	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "Jane Doe",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://api.novin-stage.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.novin-stage.com" // Set the host to staging
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusOK)
}

func TestIdentityPlugin_UnknownHostFallback(t *testing.T) {
	// Create mock default identity service
	defaultMockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"isValid":   true,
				"userId":    1,
				"username":  "default-user",
				"fullName":  "Default User",
				"roles":     []string{"user"},
				"expiresAt": "2025-08-29T16:44:08+00:00",
			},
			"message":          nil,
			"validationErrors": map[string]interface{}{},
			"isSuccess":        true,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer defaultMockServer.Close()

	cfg := plugin.CreateConfig()
	cfg.EnvironmentServices = map[string]string{
		"api.novin-system.com": "http://prod-service",
		"api.novin-stage.com":  "http://staging-service",
	}
	cfg.DefaultIdentityServiceURL = defaultMockServer.URL

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	// Create a JWT with enforce_security_stamp = true
	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "Unknown Host User",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unknown.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "unknown.example.com" // Set the host to unknown domain
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusOK)
}

func TestIdentityPlugin_BackwardCompatibility(t *testing.T) {
	// Create mock identity service
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"isValid":   true,
				"userId":    1,
				"username":  "legacy-user",
				"fullName":  "Legacy User",
				"roles":     []string{"user"},
				"expiresAt": "2025-08-29T16:44:08+00:00",
			},
			"message":          nil,
			"validationErrors": map[string]interface{}{},
			"isSuccess":        true,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Test old configuration style
	cfg := &plugin.Config{
		JWTSecretKey:       "YourSuperSecretKeyThatIsAtLeast32CharactersLong",
		IdentityServiceURL: mockServer.URL,
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	// Create a JWT with enforce_security_stamp = true
	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "Legacy User",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://legacy.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusOK)
}

// New tests for additional scenarios and edge cases

func TestIdentityPlugin_InvalidAuthorizationHeaderFormat(t *testing.T) {
	cfg := plugin.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Authorization header that does not start with "Bearer "
	req.Header.Set("Authorization", "Token sometoken")

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusUnauthorized)
}

func TestIdentityPlugin_UnsupportedSigningMethod_RS256(t *testing.T) {
	cfg := plugin.CreateConfig()

	// Create an RS256-signed token which should be rejected (plugin expects HMAC)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":  "123",
		"name": "RS User",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tokenString)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusUnauthorized)
}

func TestIdentityPlugin_NewEmptySecretKey(t *testing.T) {
	cfg := plugin.CreateConfig()
	cfg.JWTSecretKey = ""

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	if _, err := plugin.New(ctx, next, cfg, "identity-plugin-test"); err == nil {
		t.Fatalf("expected error when jwtSecretKey is empty")
	}
}

func TestIdentityPlugin_NewNoServiceConfigured(t *testing.T) {
	cfg := plugin.CreateConfig()
	cfg.EnvironmentServices = map[string]string{}
	cfg.DefaultIdentityServiceURL = ""
	cfg.IdentityServiceURL = "" // ensure legacy path not used

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	if _, err := plugin.New(ctx, next, cfg, "identity-plugin-test"); err == nil {
		t.Fatalf("expected error when no identity service URL is configured")
	}
}

func TestIdentityPlugin_IdentityServiceReturnsNon200(t *testing.T) {
	// Mock identity service returning 500
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	}))
	defer mockServer.Close()

	cfg := plugin.CreateConfig()
	cfg.DefaultIdentityServiceURL = mockServer.URL

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	// Create a JWT with enforce_security_stamp = true
	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "Non200",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusInternalServerError)
}

func TestIdentityPlugin_IdentityServiceMalformedJSON(t *testing.T) {
	// Mock identity service returning invalid JSON
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{invalid-json"))
	}))
	defer mockServer.Close()

	cfg := plugin.CreateConfig()
	cfg.DefaultIdentityServiceURL = mockServer.URL

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "Bad JSON",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusInternalServerError)
}

func TestIdentityPlugin_IdentityServiceNetworkError(t *testing.T) {
	// Create a server and close it to simulate connection error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serverURL := server.URL
	server.Close()

	cfg := plugin.CreateConfig()
	cfg.DefaultIdentityServiceURL = serverURL

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "Network Error",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusInternalServerError)
}

func TestIdentityPlugin_WildcardSubdomainMatch(t *testing.T) {
	// Mock identity service that validates
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data":      map[string]interface{}{"isValid": true},
			"isSuccess": true,
		})
	}))
	defer mockServer.Close()

	cfg := plugin.CreateConfig()
	cfg.EnvironmentServices = map[string]string{
		"*.dev.novin.local": mockServer.URL,
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "Wildcard Subdomain",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://api.dev.novin.local", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.dev.novin.local"
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusOK)
}

func TestIdentityPlugin_PrefixWildcardMatch(t *testing.T) {
	// Mock identity service that validates
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data":      map[string]interface{}{"isValid": true},
			"isSuccess": true,
		})
	}))
	defer mockServer.Close()

	cfg := plugin.CreateConfig()
	cfg.EnvironmentServices = map[string]string{
		"api.*": mockServer.URL,
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "Prefix Wildcard",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://api.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assertStatus(t, recorder.Result(), http.StatusOK)
}

func TestIdentityPlugin_HTTPTimeoutRespected(t *testing.T) {
	// Mock identity service that sleeps longer than configured timeout
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"isValid":true},"isSuccess":true}`))
	}))
	defer slowServer.Close()

    cfg := plugin.CreateConfig()
    cfg.DefaultIdentityServiceURL = slowServer.URL
    cfg.Timeout = 1 * time.Second // shorter than server sleep

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
	})

	handler, err := plugin.New(ctx, next, cfg, "identity-plugin-test")
	if err != nil {
		t.Fatal(err)
	}

	token := createTestJWT(t, cfg.JWTSecretKey, jwt.MapClaims{
		"sub":                    "1234567890",
		"name":                   "Timeout Test",
		"iat":                    time.Now().Unix(),
		"exp":                    time.Now().Add(time.Hour).Unix(),
		"enforce_security_stamp": true,
	})

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	start := time.Now()
	handler.ServeHTTP(recorder, req)
	elapsed := time.Since(start)

	// Should return 500 due to timeout and complete in ~1s, well below 2s
	assertStatus(t, recorder.Result(), http.StatusInternalServerError)
	if elapsed >= 2*time.Second {
		t.Fatalf("request did not timeout as expected; elapsed=%v", elapsed)
	}
}

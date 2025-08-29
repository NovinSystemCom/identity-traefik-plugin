# Traefik Identity Plugin

A Traefik middleware plugin for JWT-based identity management with security stamp enforcement and environment-aware identity service routing.

## Features

- **JWT Validation**: Validates JWT tokens using HMAC-SHA256 signing
- **Conditional Security**: Supports `enforce_security_stamp` claim for enhanced security checks
- **Environment-Aware Routing**: Automatically routes to production or staging identity services based on request host
- **Flexible Configuration**: Configurable JWT secret key and multiple identity service URLs
- **Pattern Matching**: Supports wildcard patterns for host matching
- **Backward Compatibility**: Maintains compatibility with single identity service URL configuration

## How It Works

1. **Authorization Header Check**: If the `Authorization` header is empty, the request passes through
2. **JWT Validation**: Validates the JWT signature using the configured secret key
3. **Security Stamp Check**: 
   - If `enforce_security_stamp` claim doesn't exist → pass through
   - If `enforce_security_stamp` is `false` → pass through
   - If `enforce_security_stamp` is not a boolean → return 401
   - If `enforce_security_stamp` is `true` → validate with identity service
4. **Environment Detection**: Determines the appropriate identity service URL based on request host
5. **Identity Service Validation**: Makes HTTP request to validate token and checks `data.isValid` field
6. **Response**: Returns 401 for invalid tokens, otherwise passes the request to the next handler

## Configuration

The plugin supports both environment-aware and legacy configuration modes:

### Environment-Aware Configuration (Recommended)

```yaml
# Static configuration
experimental:
  plugins:
    identity:
      moduleName: git.novin-tools.com/devops/traefik-identity-plugin
      version: v1.0.0

# Dynamic configuration
http:
  middlewares:
    identity-auth:
      plugin:
        identity:
          jwtSecretKey: "{{ env \"JWT_SECRET_KEY\" }}"
          environmentServices:
            "api.novin-system.com": "https://api.identity.novin-system.com/api/v1/auth/validate-token"
            "api.novin-stage.com": "https://api.identity.novin-stage.com/api/v1/auth/validate-token"
            "*.dev.novin.local": "http://localhost:5000/api/v1/auth/validate-token"
          defaultIdentityServiceURL: "https://api.identity.novin-stage.com/api/v1/auth/validate-token"
          productionDomains:
            - "api.novin-system.com"
            - "*.prod.novin.com"
          stagingDomains:
            - "api.novin-stage.com"
            - "*.stage.novin.com"

  routers:
    api:
      rule: "Host(`api.novin-system.com`) || Host(`api.novin-stage.com`)"
      middlewares:
        - identity-auth
      service: api-service
```

### Legacy Configuration (Backward Compatible)

```yaml
http:
  middlewares:
    identity-auth:
      plugin:
        identity:
          jwtSecretKey: "{{ env \"JWT_SECRET_KEY\" }}"
          identityServiceURL: "https://api.identity.novin-stage.com/api/v1/auth/validate-token"
```

### Configuration Parameters

#### Environment-Aware Parameters

- `jwtSecretKey`: The secret key used to validate JWT signatures (**required**)
- `environmentServices`: Map of host patterns to identity service URLs (recommended)
- `defaultIdentityServiceURL`: Fallback URL when no specific environment mapping exists
- `productionDomains`: List of production domain patterns for automatic routing
- `stagingDomains`: List of staging domain patterns for automatic routing

#### Legacy Parameters (Deprecated)

- `identityServiceURL`: Single identity service URL (maintained for backward compatibility)

#### Host Pattern Matching

The plugin supports several host pattern formats:

- **Exact match**: `api.novin-system.com`
- **Wildcard subdomain**: `*.novin-stage.com` (matches `api.novin-stage.com`, `auth.novin-stage.com`, etc.)
- **Prefix wildcard**: `api.*` (matches `api.example.com`, `api.test.local`, etc.)

## Environment Detection Logic

The plugin determines the appropriate identity service using this priority order:

1. **Direct Environment Service Mapping**: Exact match in `environmentServices`
2. **Pattern Matching**: Wildcard pattern match in `environmentServices`  
3. **Production Domain Check**: If host matches `productionDomains`, use production service URL
4. **Default Fallback**: Use `defaultIdentityServiceURL`
5. **Legacy Mode**: Use `identityServiceURL` if no environment services configured

## JWT Claims

The plugin expects the following JWT structure:

```json
{
  "sub": "user_id",
  "name": "User Name",
  "iat": 1234567890,
  "exp": 1234567890,
  "enforce_security_stamp": true
}
```

### Security Stamp Enforcement

The `enforce_security_stamp` claim controls additional validation:

- **Missing or `false`**: Token is validated locally only
- **`true`**: Token is validated against the identity service
- **Invalid type**: Returns 401 Unauthorized

## Identity Service API

When `enforce_security_stamp` is `true`, the plugin makes a GET request to:

```
GET {identityServiceURL}?accessToken={jwt_token}
Accept: */*
```

Expected response format:

```json
{
  "data": {
    "isValid": true,
    "userId": 2,
    "username": "username",
    "fullName": "Full Name",
    "roles": ["role1", "role2"],
    "expiresAt": "2025-08-29T16:44:08+00:00"
  },
  "message": null,
  "validationErrors": {},
  "isSuccess": true
}
```

The plugin checks the `data.isValid` field to determine if the token should be accepted.

## Development

### Prerequisites

- Go 1.21 or later
- Access to Traefik v2.5+

### Building

```bash
go mod tidy
go build
```

### Testing

```bash
go test -v ./...
```

### Local Development

1. Clone this repository
2. Update the `go.mod` with your module path
3. Build and test the plugin
4. Configure Traefik to use the plugin

## Security Considerations

- The JWT secret key should be kept secure and rotated regularly
- The identity service should use HTTPS in production
- Consider implementing rate limiting for the identity service calls
- Monitor failed authentication attempts

## License

This project is licensed under the MIT License - see the LICENSE file for details.

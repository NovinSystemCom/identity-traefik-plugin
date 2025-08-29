# Security Policy

### What to Expect

- **Acknowledgment**: We'll acknowledge receipt within 24 hours
- **Initial Assessment**: We'll provide an initial assessment within 72 hours
- **Updates**: We'll keep you informed of progress
- **Resolution**: We aim to resolve critical issues within 7 days

## Security Best Practices

### JWT Secret Key Management

- **Never hardcode** the JWT secret key in configuration files
- **Use environment variables** or secure secret management systems
- **Rotate keys regularly** (recommended: every 90 days)
- **Use keys with sufficient entropy** (minimum 32 characters)
- **Store keys securely** with appropriate access controls

### Identity Service Integration

- **Always use HTTPS** for identity service communication in production
- **Validate SSL certificates** properly
- **Implement timeouts** to prevent hanging requests
- **Monitor and log** authentication attempts
- **Rate limit** requests to prevent abuse

### Deployment Security

- **Use specific version tags** instead of latest
- **Regularly update dependencies** to patch security vulnerabilities
- **Monitor for security advisories** for Go and JWT libraries
- **Implement proper logging** without exposing sensitive information
- **Use network policies** to restrict outbound connections

### Configuration Security

```yaml
# ✅ Good - Using environment variables
http:
  middlewares:
    identity-auth:
      plugin:
        identity:
          jwtSecretKey: "{{ env \"JWT_SECRET_KEY\" }}"
          identityServiceURL: "{{ env \"IDENTITY_SERVICE_URL\" }}"

# ❌ Bad - Hardcoded secrets
http:
  middlewares:
    identity-auth:
      plugin:
        identity:
          jwtSecretKey: "YourSuperSecretKeyThatIsAtLeast32CharactersLong"
          identityServiceURL: "https://api.identity.novin-stage.com/api/v1/auth/validate-token"
```

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Features

### JWT Validation
- HMAC-SHA256 signature verification
- Token expiration validation
- Claims type validation

### Request Security
- Authorization header validation
- Bearer token format enforcement
- Invalid token rejection

### Service Integration
- Secure HTTPS communication
- Request timeout handling
- Response validation

### Error Handling
- No sensitive information in error messages
- Proper HTTP status codes
- Secure logging practices

## Known Security Considerations

1. **Token Exposure**: Ensure JWT tokens are transmitted over HTTPS only
2. **Service Availability**: Identity service downtime affects authentication
3. **Network Security**: Secure communication between Traefik and identity service
4. **Logging**: Avoid logging JWT tokens or secret keys
5. **Rate Limiting**: Consider implementing rate limiting for failed authentication attempts

## Dependencies Security

This plugin uses the following security-critical dependencies:

- `github.com/golang-jwt/jwt/v5` - JWT token handling
- Standard Go libraries for HTTP and cryptography

We monitor these dependencies for security updates and recommend keeping them updated.

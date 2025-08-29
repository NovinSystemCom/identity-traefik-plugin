# Example Traefik Configuration

This directory contains example configurations for using the Identity Plugin with Traefik.

## Docker Compose Example

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v3.0
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--experimental.plugins.identity.modulename=git.novin-tools.com/devops/traefik-identity-plugin"
      - "--experimental.plugins.identity.version=v1.0.0"
    ports:
      - "80:80"
      - "8080:8080"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
    environment:
      - JWT_SECRET_KEY=YourSuperSecretKeyThatIsAtLeast32CharactersLong
    labels:
      - "traefik.enable=true"

  app:
    image: nginx:alpine
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app-prod.rule=Host(`api.novin-system.com`)"
      - "traefik.http.routers.app-prod.entrypoints=web"
      - "traefik.http.routers.app-prod.middlewares=identity-auth"
      - "traefik.http.routers.app-staging.rule=Host(`api.novin-stage.com`)"
      - "traefik.http.routers.app-staging.entrypoints=web"
      - "traefik.http.routers.app-staging.middlewares=identity-auth"
      - "traefik.http.middlewares.identity-auth.plugin.identity.jwtSecretKey={{ env \"JWT_SECRET_KEY\" }}"
      - "traefik.http.middlewares.identity-auth.plugin.identity.environmentServices.api.novin-system.com=https://api.identity.novin-system.com/api/v1/auth/validate-token"
      - "traefik.http.middlewares.identity-auth.plugin.identity.environmentServices.api.novin-stage.com=https://api.identity.novin-stage.com/api/v1/auth/validate-token"
      - "traefik.http.middlewares.identity-auth.plugin.identity.defaultIdentityServiceURL=https://api.identity.novin-stage.com/api/v1/auth/validate-token"
```

## Static Configuration (traefik.yml)

```yaml
api:
  dashboard: true
  insecure: true

entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

providers:
  docker:
    exposedByDefault: false
  file:
    filename: /etc/traefik/dynamic.yml
    watch: true

experimental:
  plugins:
    identity:
      moduleName: git.novin-tools.com/devops/traefik-identity-plugin
      version: v1.0.0

certificatesResolvers:
  letsencrypt:
    acme:
      email: admin@example.com
      storage: acme.json
      httpChallenge:
        entryPoint: web
```

## Dynamic Configuration (dynamic.yml)

```yaml
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
    
    secure-headers:
      headers:
        accessControlAllowMethods:
          - GET
          - OPTIONS
          - PUT
          - POST
          - DELETE
        accessControlAllowOriginList:
          - "https://app.novin-system.com"
          - "https://app.novin-stage.com"
        accessControlMaxAge: 100
        addVaryHeader: true

  routers:
    api-prod-router:
      rule: "Host(`api.novin-system.com`)"
      entryPoints:
        - websecure
      middlewares:
        - identity-auth
        - secure-headers
      service: api-service
      tls:
        certResolver: letsencrypt

    api-staging-router:
      rule: "Host(`api.novin-stage.com`)"
      entryPoints:
        - websecure
      middlewares:
        - identity-auth
        - secure-headers
      service: api-service
      tls:
        certResolver: letsencrypt

    public-api-router:
      rule: "(Host(`api.novin-system.com`) || Host(`api.novin-stage.com`)) && PathPrefix(`/public`)"
      entryPoints:
        - websecure
      middlewares:
        - secure-headers
      service: api-service
      tls:
        certResolver: letsencrypt

  services:
    api-service:
      loadBalancer:
        servers:
          - url: "http://backend:8080"
```

## Kubernetes Example

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: identity-auth
  namespace: default
spec:
  plugin:
    identity:
      jwtSecretKey: "YourSuperSecretKeyThatIsAtLeast32CharactersLong"
      identityServiceURL: "https://api.identity.novin-stage.com/api/v1/auth/validate-token"

---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: api-ingress
  namespace: default
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`api.example.com`)
      kind: Rule
      middlewares:
        - name: identity-auth
          namespace: default
      services:
        - name: api-service
          port: 80
  tls:
    certResolver: letsencrypt
```

## Testing the Configuration

### 1. Without Authorization Header

```bash
curl -v http://localhost/api/health
# Expected: 200 OK (passes through)
```

### 2. With Invalid JWT

```bash
curl -v -H "Authorization: Bearer invalid.jwt.token" http://localhost/api/users
# Expected: 401 Unauthorized
```

### 3. With Valid JWT (enforce_security_stamp: false)

```bash
# Generate a JWT with enforce_security_stamp: false
TOKEN=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 -w 0)
PAYLOAD=$(echo -n '{"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":1999999999,"enforce_security_stamp":false}' | base64 -w 0)
SECRET="YourSuperSecretKeyThatIsAtLeast32CharactersLong"

curl -v -H "Authorization: Bearer ${TOKEN}.${PAYLOAD}.signature" http://localhost/api/users
# Expected: 200 OK (if JWT signature is valid)
```

### 4. With Valid JWT (enforce_security_stamp: true)

```bash
# This will make a call to the identity service
TOKEN=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 -w 0)
PAYLOAD=$(echo -n '{"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":1999999999,"enforce_security_stamp":true}' | base64 -w 0)
SECRET="YourSuperSecretKeyThatIsAtLeast32CharactersLong"

curl -v -H "Authorization: Bearer ${TOKEN}.${PAYLOAD}.signature" http://localhost/api/users
# Expected: 200 OK if identity service validates the token, 401 otherwise
```

## Environment-Specific Configuration

### Development

```yaml
http:
  middlewares:
    identity-auth-dev:
      plugin:
        identity:
          jwtSecretKey: "DevSecretKeyThatIsAtLeast32CharactersLong"
          identityServiceURL: "http://localhost:5000/api/v1/auth/validate-token"
```

### Staging

```yaml
http:
  middlewares:
    identity-auth-staging:
      plugin:
        identity:
          jwtSecretKey: "{{ env "JWT_SECRET_KEY" }}"
          identityServiceURL: "https://api.identity.novin-stage.com/api/v1/auth/validate-token"
```

### Production

```yaml
http:
  middlewares:
    identity-auth-prod:
      plugin:
        identity:
          jwtSecretKey: "{{ env "JWT_SECRET_KEY" }}"
          identityServiceURL: "https://api.identity.novin-prod.com/api/v1/auth/validate-token"
```

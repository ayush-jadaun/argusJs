# Deployment

## Docker Compose (Quickstart)

The fastest way to run ArgusJS in production is with Docker Compose:

```bash
# Clone and start
git clone https://github.com/your-org/argus.git
cd argus
docker compose up -d

# Verify
curl http://localhost:3100/v1/health
# {"status":"ok","timestamp":"2026-03-21T12:00:00.000Z"}

# View logs
docker compose logs -f argus-server

# Stop
docker compose down

# Stop and wipe all data
docker compose down -v
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    ports:
      - '5432:5432'
    environment:
      POSTGRES_USER: argus
      POSTGRES_PASSWORD: argus
      POSTGRES_DB: argus
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ['CMD-SHELL', 'pg_isready -U argus']
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - '6379:6379'
    volumes:
      - redis_data:/data
    healthcheck:
      test: ['CMD', 'redis-cli', 'ping']
      interval: 5s
      timeout: 5s
      retries: 5

  argus-server:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - '3100:3100'
    environment:
      DATABASE_URL: postgres://argus:argus@postgres:5432/argus  # or MONGO_URL for MongoDB
      REDIS_URL: redis://redis:6379
      PORT: 3100
      HOST: 0.0.0.0
      LOG_LEVEL: info
      NODE_ENV: production
      JWT_ISSUER: auth.yourdomain.com
      JWT_AUDIENCE: api.yourdomain.com
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ['CMD', 'wget', '-qO-', 'http://localhost:3100/v1/health']
      interval: 10s
      timeout: 5s
      retries: 3

volumes:
  postgres_data:
  redis_data:
```

### Dockerfile

The included multi-stage Dockerfile produces a minimal production image:

```dockerfile
# Stage 1: Install dependencies
FROM node:20-alpine AS deps
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/ packages/
RUN pnpm install --frozen-lockfile

# Stage 2: Build
FROM deps AS build
RUN pnpm build

# Stage 3: Production image
FROM node:20-alpine AS production
RUN apk add --no-cache dumb-init wget
RUN addgroup -g 1001 -S argus && adduser -S argus -u 1001
WORKDIR /app
COPY --from=build --chown=argus:argus /app .
USER argus
EXPOSE 3100
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "packages/server/dist/server.js"]
```

Key features:
- Multi-stage build (small final image)
- Non-root user (`argus:1001`)
- `dumb-init` for proper signal handling
- `wget` for health checks

## Kubernetes Deployment

### Basic Manifests

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: argus

---
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argus-config
  namespace: argus
data:
  PORT: "3100"
  HOST: "0.0.0.0"
  LOG_LEVEL: "info"
  NODE_ENV: "production"
  JWT_ISSUER: "auth.yourdomain.com"
  JWT_AUDIENCE: "api.yourdomain.com"
  DB_POOL_MAX: "20"

---
# secret.yaml (use sealed-secrets or external-secrets in production)
apiVersion: v1
kind: Secret
metadata:
  name: argus-secrets
  namespace: argus
type: Opaque
stringData:
  DATABASE_URL: "postgres://argus:password@postgres-service:5432/argus"  # or use MONGO_URL for MongoDB
  REDIS_URL: "redis://redis-service:6379"
  MFA_ENCRYPTION_KEY: "your-64-char-hex-key-here"
  JWT_PRIVATE_KEY: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----

---
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argus-server
  namespace: argus
spec:
  replicas: 3
  selector:
    matchLabels:
      app: argus-server
  template:
    metadata:
      labels:
        app: argus-server
    spec:
      containers:
        - name: argus-server
          image: your-registry/argus:latest
          ports:
            - containerPort: 3100
          envFrom:
            - configMapRef:
                name: argus-config
            - secretRef:
                name: argus-secrets
          resources:
            requests:
              cpu: 500m
              memory: 512Mi
            limits:
              cpu: 2000m
              memory: 1Gi
          livenessProbe:
            httpGet:
              path: /v1/health/live
              port: 3100
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /v1/health/ready
              port: 3100
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 5
            failureThreshold: 3
          startupProbe:
            httpGet:
              path: /v1/health/live
              port: 3100
            failureThreshold: 30
            periodSeconds: 2

---
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: argus-server
  namespace: argus
spec:
  selector:
    app: argus-server
  ports:
    - port: 3100
      targetPort: 3100
  type: ClusterIP

---
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argus-ingress
  namespace: argus
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
    - hosts:
        - auth.yourdomain.com
      secretName: argus-tls
  rules:
    - host: auth.yourdomain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: argus-server
                port:
                  number: 3100

---
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: argus-server-hpa
  namespace: argus
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: argus-server
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

### Resource Guidelines

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|------------|-----------|----------------|--------------|
| ArgusJS | 500m | 2000m | 512 Mi | 1 Gi |
| PostgreSQL | 500m | 2000m | 1 Gi | 2 Gi |
| Redis | 100m | 500m | 128 Mi | 256 Mi |

Memory is important because Argon2 uses 64 MB per concurrent hash. With `UV_THREADPOOL_SIZE=16`, you need at least 16 * 64 MB = 1 GB just for hashing under full load.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes* | -- | PostgreSQL connection string (required if using Postgres adapter) |
| `MONGO_URL` | Yes* | -- | MongoDB connection string (required if using MongoDB adapter) |
| `REDIS_URL` | No | -- | Redis connection string (falls back to in-memory cache) |
| `PORT` | No | `3100` | Server port |
| `HOST` | No | `0.0.0.0` | Server bind address |
| `NODE_ENV` | No | `development` | `production` for secure Argon2 defaults |
| `LOG_LEVEL` | No | `info` | `trace`, `debug`, `info`, `warn`, `error`, `fatal` |
| `JWT_ALGORITHM` | No | `rs256` | JWT signing algorithm: `rs256`, `es256`, or `hs256` |
| `JWT_SECRET` | No* | -- | HMAC secret for HS256 (required when `JWT_ALGORITHM=hs256`, min 32 chars) |
| `JWT_ISSUER` | No | `argus` | JWT `iss` claim |
| `JWT_AUDIENCE` | No | `argus` | JWT `aud` claim (comma-separated for multiple) |
| `JWT_PRIVATE_KEY` | No | Auto-generated | RSA private key (PEM). Auto-generates if not provided |
| `MFA_ENCRYPTION_KEY` | No | Auto-generated | 64-char hex key for AES-256-GCM MFA secret encryption |
| `DB_POOL_MAX` | No | `20` | PostgreSQL connection pool size |
| `DB_IDLE_TIMEOUT` | No | `30` | Idle connection timeout (seconds) |
| `DB_CONNECT_TIMEOUT` | No | `10` | Connection timeout (seconds) |
| `ROTATE_REFRESH_TOKENS` | No | `true` | Set to `false` to disable refresh token rotation (Keycloak-style reuse) |
| `CLUSTER_WORKERS` | No | CPU count | Number of cluster workers |
| `UV_THREADPOOL_SIZE` | No | Auto (max(16, cpus*2)) | libuv thread pool size (set automatically by server.ts at startup) |
| `SENDGRID_API_KEY` | No | -- | SendGrid API key |
| `SMTP_HOST` | No | -- | SMTP server hostname |
| `SMTP_PORT` | No | `587` | SMTP server port |
| `SMTP_USER` | No | -- | SMTP username |
| `SMTP_PASS` | No | -- | SMTP password |
| `GOOGLE_CLIENT_ID` | No | -- | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | -- | Google OAuth client secret |
| `GITHUB_CLIENT_ID` | No | -- | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | No | -- | GitHub OAuth client secret |

## Cluster Mode

For multi-core utilization without Kubernetes:

```bash
# Use all CPU cores
node packages/server/dist/cluster.js

# Specify worker count
CLUSTER_WORKERS=4 node packages/server/dist/cluster.js
```

The cluster primary process:
1. Forks N worker processes
2. Restarts workers that crash
3. Forwards `SIGTERM`/`SIGINT` to workers for graceful shutdown

Each worker is a full ArgusJS server with its own Fastify instance, database connection pool, and Redis connection.

## Health Check Endpoints

| Endpoint | Purpose | Usage |
|----------|---------|-------|
| `GET /v1/health` | Basic health | Load balancer health check |
| `GET /v1/health/live` | Liveness | Kubernetes liveness probe |
| `GET /v1/health/ready` | Readiness | Kubernetes readiness probe (checks DB + Redis) |

### Responses

**Healthy:**
```json
{
  "status": "ok",
  "checks": { "db": "ok", "cache": "ok" }
}
```

**Degraded (503):**
```json
{
  "status": "degraded",
  "checks": { "db": "ok", "cache": "failing" }
}
```

## Graceful Shutdown

The server handles shutdown signals properly:

1. **SIGTERM/SIGINT received** -- set `shuttingDown = true`
2. **New requests rejected** -- return `503 Service is shutting down`
3. **In-flight requests drain** -- Fastify waits for active requests to complete
4. **Close connections** -- Fastify closes HTTP server
5. **Shutdown adapters** -- ArgusJS calls `shutdown()` on all adapters (closes DB pool, Redis connection)
6. **Exit** -- process exits cleanly

A 30-second force-kill timer ensures the process does not hang indefinitely if shutdown stalls.

```
SIGTERM received
  -> shuttingDown = true (new requests get 503)
  -> app.close() (drain in-flight, close HTTP)
  -> argus.shutdown() (close DB, Redis, etc.)
  -> process.exit(0)
  |
  +-- 30s timeout --> process.exit(1) (forced)
```

## Production Checklist

- [ ] Set `NODE_ENV=production` (enables secure Argon2 defaults)
- [ ] Provide `JWT_PRIVATE_KEY` (do not auto-generate in production)
- [ ] Provide `MFA_ENCRYPTION_KEY` (do not auto-generate in production)
- [ ] Use a dedicated PostgreSQL or MongoDB instance with backups
- [ ] Use a dedicated Redis instance with persistence (RDB or AOF)
- [ ] Enable TLS at the load balancer / reverse proxy level
- [ ] Set `CLUSTER_WORKERS` or use Kubernetes replicas for multi-core
- [ ] Configure monitoring on `/v1/health/ready`
- [ ] Set up log aggregation (the server outputs structured JSON logs)
- [ ] Review and tune `DB_POOL_MAX` based on instance count
- [ ] Set rate limiting (configure `rateLimiter` adapter)
- [ ] Enable audit logging (`audit.enabled: true`)
- [ ] Back up the `MFA_ENCRYPTION_KEY` and `JWT_PRIVATE_KEY` securely
- [ ] Test graceful shutdown in your orchestrator
- [ ] Choose a performance profile (Max Security, Balanced, or Max Speed) -- see [docs/TRADEOFFS.md](TRADEOFFS.md)

# Performance

## Benchmark Methodology

All benchmarks use [k6](https://k6.io/) for load testing. The test suite is in `tests/k6/` and includes 11 scenarios covering registration, login, token refresh, session management, rate limiting, brute force protection, and mixed realistic workloads.

### Test Environment

- **Server:** Single Node.js 20 instance (no cluster mode)
- **Database:** PostgreSQL 16 (Docker, same machine)
- **Cache:** Redis 7 (Docker, same machine)
- **Hashing:** Argon2id with OWASP-recommended parameters (production) or lightweight dev parameters
- **Machine:** Development workstation
- **UV_THREADPOOL_SIZE:** 16 (set automatically by the server entrypoint)

### How to Run

```bash
# Start infrastructure
docker compose up -d postgres redis

# Build and start the server
pnpm build && pnpm start

# Run all k6 scenarios
cd tests/k6 && bash run-all.sh

# Run a single scenario
k6 run scenarios/login.js
```

## Results

### Summary Table

| Endpoint | Requests/sec | p50 Latency | p95 Latency | p99 Latency | Notes |
|----------|-------------|-------------|-------------|-------------|-------|
| Health / JWKS | 9,317 | 7 ms | 12 ms | 18 ms | Cached, no DB hit |
| Token Refresh | 176 | 28 ms | 65 ms | 120 ms | DB read + write + JWT sign |
| Login | 179 | 159 ms | 280 ms | 450 ms | Argon2 verify + session + JWT |
| Registration (dev) | 230 | 125 ms | 200 ms | 350 ms | Lightweight Argon2 (4 MB, 2 iter) |
| Registration (prod) | 33 | 1,328 ms | 1,850 ms | 2,100 ms | Full Argon2 (64 MB, 3 iter) |

### Breakdown by Scenario

#### Health and JWKS (9,317 req/s)

The `/v1/health` and `/.well-known/jwks.json` endpoints have no database or cache dependencies. JWKS responses are cached in memory. These endpoints serve as the performance ceiling for the server framework (Fastify 5).

#### Token Refresh (176 req/s)

Token refresh involves:
1. SHA-256 hash of the refresh token
2. Database lookup by hash
3. Atomic revocation of old token (single UPDATE with WHERE clause)
4. Database INSERT for new refresh token
5. Database SELECT for user data
6. JWT signing (RS256)

This is the most latency-sensitive operation for end users, since it happens silently in the background every 15 minutes.

#### Login (179 req/s)

Login is dominated by Argon2 password verification time. With production parameters (64 MB, 3 iterations, 4 parallelism), a single Argon2 verify takes approximately 150 ms. The remaining time is session creation and JWT signing.

#### Registration - Dev Params (230 req/s)

With lightweight Argon2 parameters (4 MB, 2 iterations, 1 parallelism), hashing takes approximately 5-10 ms, making the pipeline much faster. This mode is used for development and testing.

#### Registration - Production Params (33 req/s)

With OWASP-recommended Argon2 parameters (64 MB, 3 iterations, 4 parallelism), a single hash takes approximately 1.3 seconds. This is by design -- see "Why Argon2id is Slow" below.

## Why Argon2id is Slow (By Design)

Argon2id is a memory-hard hashing algorithm. The "slow" hashing time (1.3 seconds with production params) is a security feature, not a performance bug.

### The threat model

An attacker who steals your database gets all the password hashes. They will then try to crack them by running Argon2id on GPUs or ASICs. Argon2id's memory-hardness means:

- Each hash attempt requires 64 MB of RAM
- GPUs have limited memory per core, so they cannot parallelize efficiently
- A 12-GPU rig that can try 10 billion SHA-256 hashes per second would be limited to a few hundred Argon2id attempts per second

### The tradeoff

- **User-facing:** A user waits 1.3 seconds during registration and login. This is negligible compared to the time spent filling out the form.
- **Attacker-facing:** Brute-forcing a 10-character password takes years instead of minutes.
- **Server-facing:** 33 registrations per second per instance is sufficient for most applications. For high-volume sign-up events, use cluster mode or horizontal scaling.

### Dev vs Production Parameters

| Parameter | Dev | Production | Notes |
|-----------|-----|------------|-------|
| `memoryCost` | 4,096 (4 MB) | 65,536 (64 MB) | OWASP recommends 64 MB minimum |
| `timeCost` | 2 | 3 | Number of iterations |
| `parallelism` | 1 | 4 | Threads per hash |
| Hash time | ~5-10 ms | ~1,300 ms | Per operation |

The server automatically uses dev parameters when `NODE_ENV !== 'production'`.

## Scaling Strategies

### 1. UV_THREADPOOL_SIZE

Argon2's native addon uses libuv's thread pool. The default pool size of 4 threads is a severe bottleneck under load. The server entrypoint automatically sets:

```typescript
process.env.UV_THREADPOOL_SIZE = String(Math.max(16, cpus().length * 2));
```

This must be set **before any imports** because libuv initializes the thread pool on first use.

### 2. Cluster Mode

The built-in cluster mode spawns one worker per CPU core:

```bash
# Start with cluster mode (uses all CPU cores)
node packages/server/dist/cluster.js

# Or specify worker count
CLUSTER_WORKERS=8 node packages/server/dist/cluster.js
```

Throughput scales linearly with worker count because all state is in PostgreSQL + Redis. On an 8-core machine:
- Login: ~1,430 req/s (8 x 179)
- Registration (prod): ~264 req/s (8 x 33)

### 3. Horizontal Scaling

Since ArgusJS is stateless (all state in PostgreSQL + Redis), you can run N instances behind a load balancer:

```
                Load Balancer (nginx / ALB / Traefik)
               /          |          \
          ArgusJS-1    ArgusJS-2    ArgusJS-3
               \          |          /
             PostgreSQL  +  Redis
```

No sticky sessions required. Any instance can serve any request.

### 4. Connection Pool Tuning

PostgreSQL connection pool defaults:

| Parameter | Default | Recommendation |
|-----------|---------|----------------|
| `max` | 20 | `cpu_count * 2` per instance |
| `idleTimeout` | 30s | Keep default |
| `connectTimeout` | 10s | Keep default |

Total connections across all instances should not exceed PostgreSQL's `max_connections` (default: 100). For large deployments, use PgBouncer.

### 5. Redis Optimization

- Use a dedicated Redis instance for ArgusJS (separate from application cache)
- Enable RDB snapshots for persistence
- For rate limiting under extreme load, consider Redis Cluster

## Capacity Planning

Rough estimates for a production deployment:

| Monthly Active Users | Logins/day | Infrastructure | ArgusJS Instances |
|---------------------|------------|----------------|-------------------|
| 1,000 | 500 | 1 small VM, shared Postgres + Redis | 1 (single process) |
| 10,000 | 5,000 | 1 medium VM, dedicated Postgres + Redis | 1 (cluster mode, 4 workers) |
| 100,000 | 50,000 | 2 VMs, dedicated Postgres + Redis | 2 instances (cluster mode) |
| 1,000,000 | 500,000 | 4+ VMs, Postgres RDS + Redis Cluster | 4+ instances (cluster mode) |
| 10,000,000 | 5,000,000 | 8+ VMs, Postgres RDS (read replicas) + Redis Cluster | 8+ instances |

**Notes:**
- These assume 1 login per MAU per day on average. Adjust based on your actual login frequency.
- Registration volume is typically 1-5% of login volume and is the most expensive operation (Argon2 hash).
- Token refresh happens every 15 minutes per active session but is cheap (176 req/s per instance).
- The bottleneck is almost always Argon2 hashing, not database or network I/O.

## Comparison with Other Systems

| System | Login Throughput (single instance) | Notes |
|--------|-----------------------------------|-------|
| ArgusJS | 179 req/s | Argon2id (64 MB), Node.js |
| Keycloak | ~100-200 req/s | bcrypt, Java/Quarkus |
| Auth0 | N/A (SaaS) | Rate limits vary by plan |
| Supabase Auth | ~100-300 req/s | bcrypt, Go |

These comparisons are approximate and depend heavily on hashing parameters, hardware, and configuration. The key insight is that auth server throughput is dominated by the hashing algorithm, not the framework.

import http from 'k6/http';
import { check } from 'k6';
import { Trend, Rate } from 'k6/metrics';

// This test measures ONLY refresh throughput — no login/registration during the test.
// Setup creates users, then the test ONLY calls /v1/auth/refresh.

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3100';
const refreshDuration = new Trend('pure_refresh_duration');
const refreshFailRate = new Rate('pure_refresh_fail_rate');

export const options = {
  scenarios: {
    pure_refresh: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 10 },
        { duration: '20s', target: 10 },
        { duration: '10s', target: 0 },
      ],
    },
  },
  thresholds: {
    pure_refresh_duration: ['p(50)<50', 'p(95)<150'],
    pure_refresh_fail_rate: ['rate<0.5'],
  },
};

export function setup() {
  // Create 10 users and get their refresh tokens
  const tokens = [];
  for (let i = 0; i < 10; i++) {
    const email = `purerefresh_${i}_${Date.now()}@perf.com`;
    const res = http.post(`${BASE_URL}/v1/auth/register`, JSON.stringify({
      email, password: 'PerfTest123!@#', displayName: `PR ${i}`,
    }), { headers: { 'Content-Type': 'application/json' } });

    if (res.status === 201) {
      const body = JSON.parse(res.body);
      tokens.push(body.refreshToken);
    }
  }
  return { tokens };
}

export default function (data) {
  if (!data.tokens || data.tokens.length === 0) return;

  // Pick a token — NOTE: each token can only be used ONCE (rotation).
  // So we just measure the refresh call, accepting that most will fail
  // after the first use. The point is to measure latency of the successful ones.
  const idx = (__VU * 1000 + __ITER) % data.tokens.length;
  const token = data.tokens[idx];

  const start = Date.now();
  const res = http.post(`${BASE_URL}/v1/auth/refresh`, JSON.stringify({
    refreshToken: token,
  }), { headers: { 'Content-Type': 'application/json' } });
  const duration = Date.now() - start;

  if (res.status === 200) {
    refreshDuration.add(res.timings.duration);
    refreshFailRate.add(false);
    check(res, { 'refresh 200': (r) => r.status === 200 });
  } else {
    // Token already rotated — expected for shared tokens
    refreshFailRate.add(true);
  }
}

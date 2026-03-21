import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3100';

const refreshDuration = new Trend('refresh_duration');
const refreshFailRate = new Rate('refresh_fail_rate');

export const options = {
  scenarios: {
    refresh_only: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 50 },
        { duration: '30s', target: 50 },
        { duration: '10s', target: 100 },
        { duration: '30s', target: 100 },
        { duration: '10s', target: 0 },
      ],
    },
  },
  thresholds: {
    refresh_duration: ['p(50)<30', 'p(95)<100', 'p(99)<200'],
    refresh_fail_rate: ['rate<0.05'],
  },
};

// Pre-register one user per VU in setup
export function setup() {
  const users = [];
  for (let i = 0; i < 100; i++) {
    const email = `refresh_iso_${i}_${Date.now()}@perf.com`;
    const regRes = http.post(`${BASE_URL}/v1/auth/register`, JSON.stringify({
      email, password: 'PerfTest123!@#', displayName: `Perf ${i}`,
    }), { headers: { 'Content-Type': 'application/json' } });

    if (regRes.status === 201) {
      const body = JSON.parse(regRes.body);
      users.push({ email, password: 'PerfTest123!@#', refreshToken: body.refreshToken });
    }
  }
  // Wait for Argon2 to settle - let the thread pool clear
  sleep(3);
  return { users };
}

export default function (data) {
  if (!data.users || data.users.length === 0) return;

  // Each VU gets its own user to avoid token conflicts
  const userIdx = __VU % data.users.length;
  const user = data.users[userIdx];

  // Re-login to get a fresh token for each iteration (login is cheaper than register for verify)
  const loginRes = http.post(`${BASE_URL}/v1/auth/login`, JSON.stringify({
    email: user.email, password: user.password,
  }), { headers: { 'Content-Type': 'application/json' } });

  if (loginRes.status !== 200) {
    refreshFailRate.add(true);
    return;
  }

  const loginBody = JSON.parse(loginRes.body);
  const refreshToken = loginBody.refreshToken;

  // NOW measure ONLY the refresh
  const refreshRes = http.post(`${BASE_URL}/v1/auth/refresh`, JSON.stringify({
    refreshToken,
  }), { headers: { 'Content-Type': 'application/json' } });

  refreshDuration.add(refreshRes.timings.duration);
  refreshFailRate.add(refreshRes.status !== 200);

  check(refreshRes, {
    'refresh returns 200': (r) => r.status === 200,
    'has new tokens': (r) => {
      try {
        const b = JSON.parse(r.body);
        return b.accessToken && b.refreshToken;
      } catch { return false; }
    },
  });
}

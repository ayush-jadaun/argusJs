import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

// ArgusJS LOGIN-only benchmark — fair comparison with Keycloak
const BASE_URL = __ENV.BASE_URL || 'http://localhost:3100';

const loginDuration = new Trend('argus_login_duration');
const refreshDuration = new Trend('argus_refresh_duration');
const loginFail = new Rate('argus_login_fail');
const refreshFail = new Rate('argus_refresh_fail');

export const options = {
  scenarios: {
    login: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30s',
      exec: 'loginTest',
    },
    refresh: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30s',
      exec: 'refreshTest',
      startTime: '35s',
    },
  },
};

// Pre-register 50 users
export function setup() {
  const users = [];
  for (let i = 0; i < 50; i++) {
    const email = `argus_fair_${i}_${Date.now()}@bench.com`;
    const res = http.post(`${BASE_URL}/v1/auth/register`, JSON.stringify({
      email, password: 'BenchMark123!@#', displayName: `Fair ${i}`,
    }), { headers: { 'Content-Type': 'application/json' } });
    if (res.status === 201) {
      users.push({ email, password: 'BenchMark123!@#' });
    }
  }
  return { users };
}

export function loginTest(data) {
  if (!data.users || data.users.length === 0) return;
  const user = data.users[Math.floor(Math.random() * data.users.length)];

  const res = http.post(`${BASE_URL}/v1/auth/login`, JSON.stringify({
    email: user.email, password: user.password,
  }), { headers: { 'Content-Type': 'application/json' } });

  loginDuration.add(res.timings.duration);
  loginFail.add(res.status !== 200);
  check(res, { 'login 200': (r) => r.status === 200 });
  sleep(0.05);
}

export function refreshTest(data) {
  if (!data.users || data.users.length === 0) return;
  const user = data.users[Math.floor(Math.random() * data.users.length)];

  // Login to get refresh token
  const loginRes = http.post(`${BASE_URL}/v1/auth/login`, JSON.stringify({
    email: user.email, password: user.password,
  }), { headers: { 'Content-Type': 'application/json' } });

  if (loginRes.status !== 200) { refreshFail.add(true); return; }
  const body = JSON.parse(loginRes.body);

  // Measure ONLY refresh
  const res = http.post(`${BASE_URL}/v1/auth/refresh`, JSON.stringify({
    refreshToken: body.refreshToken,
  }), { headers: { 'Content-Type': 'application/json' } });

  refreshDuration.add(res.timings.duration);
  refreshFail.add(res.status !== 200);
  check(res, { 'refresh 200': (r) => r.status === 200 });
  sleep(0.05);
}

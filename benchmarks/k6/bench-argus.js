import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3100';

// Metrics
const registerDuration = new Trend('argus_register_duration');
const loginDuration = new Trend('argus_login_duration');
const refreshDuration = new Trend('argus_refresh_duration');
const registerFail = new Rate('argus_register_fail_rate');
const loginFail = new Rate('argus_login_fail_rate');
const refreshFail = new Rate('argus_refresh_fail_rate');
const totalOps = new Counter('argus_total_ops');

export const options = {
  scenarios: {
    registration: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30s',
      exec: 'registration',
    },
    login: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30s',
      exec: 'login',
      startTime: '35s', // start after registration
    },
    refresh: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30s',
      exec: 'tokenRefresh',
      startTime: '70s', // start after login
    },
  },
};

// ========== REGISTRATION ==========
export function registration() {
  const email = `argus_${__VU}_${__ITER}_${Date.now()}@bench.com`;
  const res = http.post(`${BASE_URL}/v1/auth/register`, JSON.stringify({
    email,
    password: 'BenchMark123!@#',
    displayName: `Bench ${__VU}`,
  }), { headers: { 'Content-Type': 'application/json' } });

  registerDuration.add(res.timings.duration);
  registerFail.add(res.status !== 201);
  totalOps.add(1);

  check(res, { 'register 201': (r) => r.status === 201 });
  sleep(0.05);
}

// ========== LOGIN ==========
// Setup: pre-register users
const loginUsers = [];
export function setup() {
  // Pre-register 50 users for login tests
  for (let i = 0; i < 50; i++) {
    const email = `argus_login_${i}_${Date.now()}@bench.com`;
    const res = http.post(`${BASE_URL}/v1/auth/register`, JSON.stringify({
      email, password: 'BenchMark123!@#', displayName: `Login ${i}`,
    }), { headers: { 'Content-Type': 'application/json' } });

    if (res.status === 201) {
      loginUsers.push({ email, password: 'BenchMark123!@#' });
    }
  }
  return { loginUsers };
}

export function login(data) {
  if (!data.loginUsers || data.loginUsers.length === 0) return;
  const user = data.loginUsers[Math.floor(Math.random() * data.loginUsers.length)];

  const res = http.post(`${BASE_URL}/v1/auth/login`, JSON.stringify({
    email: user.email,
    password: user.password,
  }), { headers: { 'Content-Type': 'application/json' } });

  loginDuration.add(res.timings.duration);
  loginFail.add(res.status !== 200);
  totalOps.add(1);

  check(res, { 'login 200': (r) => r.status === 200 });
  sleep(0.05);
}

// ========== TOKEN REFRESH ==========
export function tokenRefresh(data) {
  if (!data.loginUsers || data.loginUsers.length === 0) return;
  const user = data.loginUsers[Math.floor(Math.random() * data.loginUsers.length)];

  // Login first to get a fresh refresh token
  const loginRes = http.post(`${BASE_URL}/v1/auth/login`, JSON.stringify({
    email: user.email, password: user.password,
  }), { headers: { 'Content-Type': 'application/json' } });

  if (loginRes.status !== 200) return;
  const body = JSON.parse(loginRes.body);

  // Now measure ONLY the refresh
  const res = http.post(`${BASE_URL}/v1/auth/refresh`, JSON.stringify({
    refreshToken: body.refreshToken,
  }), { headers: { 'Content-Type': 'application/json' } });

  refreshDuration.add(res.timings.duration);
  refreshFail.add(res.status !== 200);
  totalOps.add(1);

  check(res, { 'refresh 200': (r) => r.status === 200 });
  sleep(0.05);
}

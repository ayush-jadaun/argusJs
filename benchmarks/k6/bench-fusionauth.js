import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

const FA_URL = __ENV.FA_URL || 'http://localhost:9011';
const API_KEY = __ENV.FA_API_KEY || ''; // Set after FusionAuth setup
const APP_ID = __ENV.FA_APP_ID || '';   // Set after FusionAuth setup

// Metrics
const registerDuration = new Trend('fusionauth_register_duration');
const loginDuration = new Trend('fusionauth_login_duration');
const refreshDuration = new Trend('fusionauth_refresh_duration');
const registerFail = new Rate('fusionauth_register_fail_rate');
const loginFail = new Rate('fusionauth_login_fail_rate');
const refreshFail = new Rate('fusionauth_refresh_fail_rate');
const totalOps = new Counter('fusionauth_total_ops');

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
      startTime: '35s',
    },
    refresh: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30s',
      exec: 'tokenRefresh',
      startTime: '70s',
    },
  },
};

// ========== REGISTRATION ==========
export function registration() {
  const email = `fa_${__VU}_${__ITER}_${Date.now()}@bench.com`;
  const res = http.post(`${FA_URL}/api/user/registration`, JSON.stringify({
    user: {
      email: email,
      password: 'BenchMark123!@#',
    },
    registration: {
      applicationId: APP_ID,
    },
  }), {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': API_KEY,
    },
  });

  registerDuration.add(res.timings.duration);
  registerFail.add(res.status !== 200);
  totalOps.add(1);

  check(res, { 'register 200': (r) => r.status === 200 });
  sleep(0.05);
}

// ========== LOGIN ==========
export function setup() {
  const users = [];
  for (let i = 0; i < 50; i++) {
    const email = `fa_login_${i}_${Date.now()}@bench.com`;
    const res = http.post(`${FA_URL}/api/user/registration`, JSON.stringify({
      user: { email, password: 'BenchMark123!@#' },
      registration: { applicationId: APP_ID },
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': API_KEY,
      },
    });

    if (res.status === 200) {
      users.push({ email, password: 'BenchMark123!@#' });
    }
  }
  return { loginUsers: users };
}

export function login(data) {
  if (!data.loginUsers || data.loginUsers.length === 0) return;
  const user = data.loginUsers[Math.floor(Math.random() * data.loginUsers.length)];

  const res = http.post(`${FA_URL}/api/login`, JSON.stringify({
    loginId: user.email,
    password: user.password,
    applicationId: APP_ID,
  }), {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': API_KEY,
    },
  });

  loginDuration.add(res.timings.duration);
  loginFail.add(res.status !== 200);
  totalOps.add(1);

  check(res, { 'login 200': (r) => r.status === 200 || r.status === 202 });
  sleep(0.05);
}

// ========== TOKEN REFRESH ==========
export function tokenRefresh(data) {
  if (!data.loginUsers || data.loginUsers.length === 0) return;
  const user = data.loginUsers[Math.floor(Math.random() * data.loginUsers.length)];

  // Login to get refresh token
  const loginRes = http.post(`${FA_URL}/api/login`, JSON.stringify({
    loginId: user.email,
    password: user.password,
    applicationId: APP_ID,
  }), {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': API_KEY,
    },
  });

  if (loginRes.status !== 200 && loginRes.status !== 202) return;
  const body = JSON.parse(loginRes.body);
  if (!body.refreshToken) return;

  // Measure ONLY the refresh
  const res = http.post(`${FA_URL}/api/jwt/refresh`, JSON.stringify({
    refreshToken: body.refreshToken,
  }), {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': API_KEY,
    },
  });

  refreshDuration.add(res.timings.duration);
  refreshFail.add(res.status !== 200);
  totalOps.add(1);

  check(res, { 'refresh 200': (r) => r.status === 200 });
  sleep(0.05);
}

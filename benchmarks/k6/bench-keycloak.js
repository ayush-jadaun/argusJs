import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

const KC_URL = __ENV.KC_URL || 'http://localhost:8080';
const REALM = __ENV.KC_REALM || 'benchmark';
const CLIENT_ID = 'bench-client';

// Metrics
const registerDuration = new Trend('keycloak_register_duration');
const loginDuration = new Trend('keycloak_login_duration');
const refreshDuration = new Trend('keycloak_refresh_duration');
const registerFail = new Rate('keycloak_register_fail_rate');
const loginFail = new Rate('keycloak_login_fail_rate');
const refreshFail = new Rate('keycloak_refresh_fail_rate');
const totalOps = new Counter('keycloak_total_ops');

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

// Helper: get admin token
function getAdminToken() {
  const res = http.post(`${KC_URL}/realms/master/protocol/openid-connect/token`, {
    client_id: 'admin-cli',
    username: 'admin',
    password: 'admin',
    grant_type: 'password',
  });
  if (res.status !== 200) return null;
  return JSON.parse(res.body).access_token;
}

// ========== REGISTRATION ==========
// Keycloak registration via Admin REST API (since self-registration requires browser flow)
export function registration() {
  const adminToken = getAdminToken();
  if (!adminToken) {
    registerFail.add(true);
    return;
  }

  const email = `kc_${__VU}_${__ITER}_${Date.now()}@bench.com`;
  const res = http.post(`${KC_URL}/admin/realms/${REALM}/users`, JSON.stringify({
    username: email,
    email: email,
    enabled: true,
    emailVerified: true,
    credentials: [{
      type: 'password',
      value: 'BenchMark123!@#',
      temporary: false,
    }],
  }), {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${adminToken}`,
    },
  });

  registerDuration.add(res.timings.duration);
  registerFail.add(res.status !== 201);
  totalOps.add(1);

  check(res, { 'register 201': (r) => r.status === 201 });
  sleep(0.05);
}

// ========== LOGIN ==========
export function setup() {
  // Pre-register 50 users via admin API
  const adminToken = getAdminToken();
  const users = [];

  if (adminToken) {
    for (let i = 0; i < 50; i++) {
      const email = `kc_login_${i}_${Date.now()}@bench.com`;
      const res = http.post(`${KC_URL}/admin/realms/${REALM}/users`, JSON.stringify({
        username: email,
        email: email,
        enabled: true,
        emailVerified: true,
        credentials: [{ type: 'password', value: 'BenchMark123!@#', temporary: false }],
      }), {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`,
        },
      });

      if (res.status === 201) {
        users.push({ email, password: 'BenchMark123!@#' });
      }
    }
  }

  return { loginUsers: users };
}

export function login(data) {
  if (!data.loginUsers || data.loginUsers.length === 0) return;
  const user = data.loginUsers[Math.floor(Math.random() * data.loginUsers.length)];

  // Keycloak login via direct access grant (Resource Owner Password Credentials)
  const res = http.post(`${KC_URL}/realms/${REALM}/protocol/openid-connect/token`, {
    client_id: CLIENT_ID,
    username: user.email,
    password: user.password,
    grant_type: 'password',
  });

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

  // Login to get refresh token
  const loginRes = http.post(`${KC_URL}/realms/${REALM}/protocol/openid-connect/token`, {
    client_id: CLIENT_ID,
    username: user.email,
    password: user.password,
    grant_type: 'password',
  });

  if (loginRes.status !== 200) return;
  const tokens = JSON.parse(loginRes.body);

  // Measure ONLY the refresh
  const res = http.post(`${KC_URL}/realms/${REALM}/protocol/openid-connect/token`, {
    client_id: CLIENT_ID,
    refresh_token: tokens.refresh_token,
    grant_type: 'refresh_token',
  });

  refreshDuration.add(res.timings.duration);
  refreshFail.add(res.status !== 200);
  totalOps.add(1);

  check(res, { 'refresh 200': (r) => r.status === 200 });
  sleep(0.05);
}

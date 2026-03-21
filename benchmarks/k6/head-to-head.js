import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

// ==========================================
// HEAD-TO-HEAD: ArgusJS vs Keycloak
// Tests LOGIN + TOKEN REFRESH side by side
// Run twice: once with --env TARGET=argus, once with --env TARGET=keycloak
// ==========================================

const TARGET = __ENV.TARGET || 'argus'; // 'argus' or 'keycloak'
const ARGUS_URL = __ENV.ARGUS_URL || 'http://localhost:3100';
const KC_URL = __ENV.KC_URL || 'http://localhost:8090';

const loginDuration = new Trend(`${TARGET}_login_ms`);
const refreshDuration = new Trend(`${TARGET}_refresh_ms`);
const loginFail = new Rate(`${TARGET}_login_fail`);
const refreshFail = new Rate(`${TARGET}_refresh_fail`);

export const options = {
  scenarios: {
    login_test: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30s',
      exec: 'loginTest',
    },
    refresh_test: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30s',
      exec: 'refreshTest',
      startTime: '35s',
    },
  },
};

// ========== ARGUS LOGIN ==========
function argusLogin(email, password) {
  return http.post(`${ARGUS_URL}/v1/auth/login`, JSON.stringify({
    email, password,
  }), { headers: { 'Content-Type': 'application/json' } });
}

function argusRefresh(refreshToken) {
  return http.post(`${ARGUS_URL}/v1/auth/refresh`, JSON.stringify({
    refreshToken,
  }), { headers: { 'Content-Type': 'application/json' } });
}

// ========== KEYCLOAK LOGIN ==========
function keycloakLogin(username, password) {
  return http.post(`${KC_URL}/realms/benchmark/protocol/openid-connect/token`, {
    client_id: 'bench-client',
    username: username,
    password: password,
    grant_type: 'password',
  });
}

function keycloakRefresh(refreshToken) {
  return http.post(`${KC_URL}/realms/benchmark/protocol/openid-connect/token`, {
    client_id: 'bench-client',
    refresh_token: refreshToken,
    grant_type: 'refresh_token',
  });
}

// ========== SETUP ==========
export function setup() {
  if (TARGET === 'argus') {
    // Pre-register 20 users
    const users = [];
    for (let i = 0; i < 20; i++) {
      const email = `h2h_${i}_${Date.now()}@bench.com`;
      const res = http.post(`${ARGUS_URL}/v1/auth/register`, JSON.stringify({
        email, password: 'BenchPass123!@#', displayName: `H2H ${i}`,
      }), { headers: { 'Content-Type': 'application/json' } });
      if (res.status === 201) {
        users.push({ username: email, password: 'BenchPass123!@#' });
      }
    }
    return { users };
  } else {
    // Keycloak users already created: kb1..kb20
    const users = [];
    for (let i = 1; i <= 20; i++) {
      users.push({ username: `kb${i}`, password: 'BenchPass123' });
    }
    return { users };
  }
}

// ========== LOGIN TEST ==========
export function loginTest(data) {
  const user = data.users[(__VU + __ITER) % data.users.length];
  let res;

  if (TARGET === 'argus') {
    res = argusLogin(user.username, user.password);
  } else {
    res = keycloakLogin(user.username, user.password);
  }

  loginDuration.add(res.timings.duration);
  loginFail.add(res.status !== 200);
  check(res, { 'login 200': (r) => r.status === 200 });
  sleep(0.05);
}

// ========== REFRESH TEST ==========
export function refreshTest(data) {
  const user = data.users[(__VU + __ITER) % data.users.length];
  let loginRes, refreshRes;

  if (TARGET === 'argus') {
    loginRes = argusLogin(user.username, user.password);
    if (loginRes.status !== 200) { refreshFail.add(true); return; }
    const body = JSON.parse(loginRes.body);
    refreshRes = argusRefresh(body.refreshToken);
  } else {
    loginRes = keycloakLogin(user.username, user.password);
    if (loginRes.status !== 200) { refreshFail.add(true); return; }
    const body = JSON.parse(loginRes.body);
    refreshRes = keycloakRefresh(body.refresh_token);
  }

  refreshDuration.add(refreshRes.timings.duration);
  refreshFail.add(refreshRes.status !== 200);
  check(refreshRes, { 'refresh 200': (r) => r.status === 200 });
  sleep(0.05);
}

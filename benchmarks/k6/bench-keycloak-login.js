import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

// Simple Keycloak LOGIN-only benchmark — fair comparison with ArgusJS
const KC_URL = __ENV.KC_URL || 'http://localhost:8090';
const REALM = 'benchmark';

const loginDuration = new Trend('kc_login_duration');
const refreshDuration = new Trend('kc_refresh_duration');
const loginFail = new Rate('kc_login_fail');
const refreshFail = new Rate('kc_refresh_fail');

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

export function loginTest() {
  const userNum = ((__VU * 100 + __ITER) % 50) + 1;
  const res = http.post(`${KC_URL}/realms/${REALM}/protocol/openid-connect/token`, {
    client_id: 'bench-client',
    username: `kcbench${userNum}`,
    password: 'BenchMark123',
    grant_type: 'password',
  });

  loginDuration.add(res.timings.duration);
  loginFail.add(res.status !== 200);
  check(res, { 'login 200': (r) => r.status === 200 });
  sleep(0.05);
}

export function refreshTest() {
  const userNum = ((__VU * 100 + __ITER) % 50) + 1;

  // Login to get refresh token
  const loginRes = http.post(`${KC_URL}/realms/${REALM}/protocol/openid-connect/token`, {
    client_id: 'bench-client',
    username: `kcbench${userNum}`,
    password: 'BenchMark123',
    grant_type: 'password',
  });

  if (loginRes.status !== 200) { refreshFail.add(true); return; }
  const tokens = JSON.parse(loginRes.body);

  // Measure ONLY the refresh
  const res = http.post(`${KC_URL}/realms/${REALM}/protocol/openid-connect/token`, {
    client_id: 'bench-client',
    refresh_token: tokens.refresh_token,
    grant_type: 'refresh_token',
  });

  refreshDuration.add(res.timings.duration);
  refreshFail.add(res.status !== 200);
  check(res, { 'refresh 200': (r) => r.status === 200 });
  sleep(0.05);
}

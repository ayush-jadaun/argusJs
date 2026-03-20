import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { BASE_URL, STAGES_LOAD } from '../config.js';
import { registerUser, loginUser, refreshToken, authHeaders } from '../helpers/auth.js';

const opDuration = new Trend('operation_duration');

export const options = {
  scenarios: {
    token_refresh: {
      executor: 'constant-arrival-rate',
      rate: 85,
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 50,
      exec: 'tokenRefresh',
    },
    login: {
      executor: 'constant-arrival-rate',
      rate: 10,
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 20,
      exec: 'loginFlow',
    },
    registration: {
      executor: 'constant-arrival-rate',
      rate: 3,
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 10,
      exec: 'registrationFlow',
    },
    profile: {
      executor: 'constant-arrival-rate',
      rate: 2,
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 5,
      exec: 'profileFlow',
    },
  },
  thresholds: {
    operation_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.05'],
  },
};

export function setup() {
  const users = [];
  for (let i = 0; i < 50; i++) {
    const email = `mixed_${i}_${Date.now()}@loadtest.com`;
    const password = 'LoadTest123!@#';
    registerUser(email, password, `Mixed ${i}`);
    const login = loginUser(email, password);
    users.push({ email, password, ...login });
  }
  return { users };
}

export function tokenRefresh(data) {
  const user = data.users[Math.floor(Math.random() * data.users.length)];
  const res = http.post(`${BASE_URL}/v1/auth/refresh`, JSON.stringify({
    refreshToken: user.refreshToken,
  }), { headers: { 'Content-Type': 'application/json' } });
  opDuration.add(res.timings.duration);
  check(res, { 'refresh ok': (r) => r.status === 200 || r.status === 401 });
}

export function loginFlow(data) {
  const user = data.users[Math.floor(Math.random() * data.users.length)];
  const res = http.post(`${BASE_URL}/v1/auth/login`, JSON.stringify({
    email: user.email, password: user.password,
  }), { headers: { 'Content-Type': 'application/json' } });
  opDuration.add(res.timings.duration);
  check(res, { 'login ok': (r) => r.status === 200 });
}

export function registrationFlow() {
  const email = `mixed_reg_${__VU}_${__ITER}_${Date.now()}@loadtest.com`;
  const res = http.post(`${BASE_URL}/v1/auth/register`, JSON.stringify({
    email, password: 'LoadTest123!@#', displayName: `MixReg ${__VU}`,
  }), { headers: { 'Content-Type': 'application/json' } });
  opDuration.add(res.timings.duration);
  check(res, { 'register ok': (r) => r.status === 201 });
}

export function profileFlow(data) {
  const user = data.users[Math.floor(Math.random() * data.users.length)];
  const res = http.get(`${BASE_URL}/v1/auth/me`, authHeaders(user.accessToken));
  opDuration.add(res.timings.duration);
  check(res, { 'profile ok': (r) => r.status === 200 || r.status === 401 });
}

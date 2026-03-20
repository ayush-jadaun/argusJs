import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';
import { BASE_URL } from '../config.js';
import { registerUser } from '../helpers/auth.js';

const concurrentLogins = new Counter('concurrent_login_attempts');

export const options = {
  vus: 50,
  duration: '30s',
  thresholds: {
    http_req_failed: ['rate<0.05'],
  },
};

// ALL VUs login as the SAME user — tests session limit enforcement
export function setup() {
  const email = `concurrent_${Date.now()}@loadtest.com`;
  registerUser(email, 'LoadTest123!@#', 'ConcurrentTest');
  return { email, password: 'LoadTest123!@#' };
}

export default function (data) {
  concurrentLogins.add(1);
  const res = http.post(`${BASE_URL}/v1/auth/login`, JSON.stringify({
    email: data.email,
    password: data.password,
  }), { headers: { 'Content-Type': 'application/json' } });

  check(res, {
    'login succeeds or locked': (r) => r.status === 200 || r.status === 423,
  });

  sleep(0.5);
}

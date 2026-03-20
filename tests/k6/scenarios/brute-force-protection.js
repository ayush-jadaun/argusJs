import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';
import { BASE_URL } from '../config.js';
import { registerUser } from '../helpers/auth.js';

const blockedCount = new Counter('blocked_attempts');

export const options = {
  vus: 1,
  iterations: 25,
};

export function setup() {
  const email = `brute_${Date.now()}@loadtest.com`;
  registerUser(email, 'LoadTest123!@#', 'BruteTest');
  return { email };
}

export default function (data) {
  const res = http.post(`${BASE_URL}/v1/auth/login`, JSON.stringify({
    email: data.email,
    password: 'WRONG_PASSWORD',
  }), { headers: { 'Content-Type': 'application/json' } });

  if (res.status === 423) {
    blockedCount.add(1);
    check(res, {
      'locked returns 423': (r) => r.status === 423,
      'has error message': (r) => JSON.parse(r.body).error.code === 'ACCOUNT_LOCKED',
    });
  } else {
    check(res, {
      'wrong password returns 401': (r) => r.status === 401,
    });
  }

  sleep(0.1);
}

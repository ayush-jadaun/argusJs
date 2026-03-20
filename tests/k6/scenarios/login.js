import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { BASE_URL, STAGES_LOAD } from '../config.js';
import { registerUser } from '../helpers/auth.js';

const loginDuration = new Trend('login_duration');
const loginFailRate = new Rate('login_fail_rate');

export const options = {
  stages: STAGES_LOAD,
  thresholds: {
    login_duration: ['p(95)<300', 'p(99)<500'],
    login_fail_rate: ['rate<0.01'],
  },
};

const TEST_USERS = [];

export function setup() {
  // Pre-register 100 users
  for (let i = 0; i < 100; i++) {
    const email = `logintest_${i}@loadtest.com`;
    const password = 'LoadTest123!@#';
    registerUser(email, password, `LoginTest ${i}`);
    TEST_USERS.push({ email, password });
  }
  return { users: TEST_USERS };
}

export default function (data) {
  const user = data.users[Math.floor(Math.random() * data.users.length)];
  const res = http.post(`${BASE_URL}/v1/auth/login`, JSON.stringify({
    email: user.email,
    password: user.password,
  }), { headers: { 'Content-Type': 'application/json' } });

  loginDuration.add(res.timings.duration);
  loginFailRate.add(res.status !== 200);

  check(res, {
    'login returns 200': (r) => r.status === 200,
    'has accessToken': (r) => JSON.parse(r.body).accessToken !== undefined,
  });

  sleep(0.1);
}

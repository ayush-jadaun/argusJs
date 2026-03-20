import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';
import { BASE_URL } from '../config.js';
import { registerUser } from '../helpers/auth.js';

const forgotDuration = new Trend('forgot_password_duration');

export const options = {
  stages: [
    { duration: '10s', target: 10 },
    { duration: '30s', target: 10 },
    { duration: '10s', target: 0 },
  ],
  thresholds: {
    forgot_password_duration: ['p(95)<200'],
  },
};

export function setup() {
  const users = [];
  for (let i = 0; i < 20; i++) {
    const email = `reset_${i}@loadtest.com`;
    registerUser(email, 'LoadTest123!@#', `Reset ${i}`);
    users.push(email);
  }
  return { users };
}

export default function (data) {
  const email = data.users[Math.floor(Math.random() * data.users.length)];
  const res = http.post(`${BASE_URL}/v1/auth/forgot-password`, JSON.stringify({ email }), {
    headers: { 'Content-Type': 'application/json' },
  });

  forgotDuration.add(res.timings.duration);

  check(res, {
    'forgot-password returns 202': (r) => r.status === 202,
  });

  sleep(0.5);
}

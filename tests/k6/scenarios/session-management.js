import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';
import { BASE_URL } from '../config.js';
import { registerUser, loginUser, authHeaders } from '../helpers/auth.js';

const sessionListDuration = new Trend('session_list_duration');
const profileDuration = new Trend('profile_duration');

export const options = {
  stages: [
    { duration: '10s', target: 20 },
    { duration: '1m', target: 20 },
    { duration: '10s', target: 0 },
  ],
  thresholds: {
    session_list_duration: ['p(95)<100'],
    profile_duration: ['p(95)<100'],
  },
};

export function setup() {
  const email = `session_${Date.now()}@loadtest.com`;
  registerUser(email, 'LoadTest123!@#', 'SessionTest');
  const login = loginUser(email, 'LoadTest123!@#');
  return { accessToken: login.accessToken };
}

export default function (data) {
  // GET /v1/auth/me
  const profileRes = http.get(`${BASE_URL}/v1/auth/me`, authHeaders(data.accessToken));
  profileDuration.add(profileRes.timings.duration);
  check(profileRes, { 'profile returns 200': (r) => r.status === 200 });

  // GET /v1/auth/sessions
  const sessionsRes = http.get(`${BASE_URL}/v1/auth/sessions`, authHeaders(data.accessToken));
  sessionListDuration.add(sessionsRes.timings.duration);
  check(sessionsRes, { 'sessions returns 200': (r) => r.status === 200 });

  sleep(0.5);
}

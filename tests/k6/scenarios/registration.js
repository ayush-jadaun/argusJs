import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { BASE_URL, STAGES_LOAD } from '../config.js';

const registrationDuration = new Trend('registration_duration');
const registrationFailRate = new Rate('registration_fail_rate');

export const options = {
  stages: STAGES_LOAD,
  thresholds: {
    registration_duration: ['p(95)<500', 'p(99)<1000'],
    registration_fail_rate: ['rate<0.01'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const email = `user_${__VU}_${__ITER}_${Date.now()}@loadtest.com`;
  const res = http.post(`${BASE_URL}/v1/auth/register`, JSON.stringify({
    email,
    password: 'LoadTest123!@#',
    displayName: `User ${__VU}`,
  }), { headers: { 'Content-Type': 'application/json' } });

  registrationDuration.add(res.timings.duration);
  registrationFailRate.add(res.status !== 201);

  check(res, {
    'registration returns 201': (r) => r.status === 201,
    'has accessToken': (r) => JSON.parse(r.body).accessToken !== undefined,
    'has refreshToken': (r) => JSON.parse(r.body).refreshToken !== undefined,
  });

  sleep(0.1);
}

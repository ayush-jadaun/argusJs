import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import { BASE_URL, STAGES_LOAD } from '../config.js';
import { registerUser, loginUser } from '../helpers/auth.js';

const refreshDuration = new Trend('refresh_duration');
const refreshFailRate = new Rate('refresh_fail_rate');

export const options = {
  stages: STAGES_LOAD,
  thresholds: {
    refresh_duration: ['p(95)<50', 'p(99)<100'],
    refresh_fail_rate: ['rate<0.01'],
  },
};

export function setup() {
  const email = `refresh_setup_${Date.now()}@loadtest.com`;
  registerUser(email, 'LoadTest123!@#', 'RefreshTest');
  const login = loginUser(email, 'LoadTest123!@#');
  return { refreshToken: login.refreshToken };
}

export default function (data) {
  // Each VU registers its own user for independent refresh tokens
  if (!__ENV.REFRESH_TOKEN) {
    const email = `refresh_${__VU}_${Date.now()}@loadtest.com`;
    registerUser(email, 'LoadTest123!@#', `Refresh ${__VU}`);
    const login = loginUser(email, 'LoadTest123!@#');

    const res = http.post(`${BASE_URL}/v1/auth/refresh`, JSON.stringify({
      refreshToken: login.refreshToken,
    }), { headers: { 'Content-Type': 'application/json' } });

    refreshDuration.add(res.timings.duration);
    refreshFailRate.add(res.status !== 200);

    check(res, {
      'refresh returns 200': (r) => r.status === 200,
      'has new accessToken': (r) => JSON.parse(r.body).accessToken !== undefined,
      'has new refreshToken': (r) => JSON.parse(r.body).refreshToken !== undefined,
    });
  }
  sleep(0.5);
}

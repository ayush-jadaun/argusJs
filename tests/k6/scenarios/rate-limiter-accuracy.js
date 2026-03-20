import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { BASE_URL } from '../config.js';

const rateLimited = new Counter('rate_limited_count');
const allowed = new Counter('allowed_count');

export const options = {
  vus: 1,
  iterations: 200,
};

export default function () {
  const res = http.get(`${BASE_URL}/v1/health`);

  if (res.status === 429) {
    rateLimited.add(1);
    check(res, {
      'rate limit has Retry-After': (r) => r.headers['Retry-After'] !== undefined || r.headers['retry-after'] !== undefined,
    });
  } else {
    allowed.add(1);
    check(res, {
      'health returns 200': (r) => r.status === 200,
    });
  }
}

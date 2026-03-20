export const BASE_URL = __ENV.BASE_URL || 'http://localhost:3100';

export const THRESHOLDS = {
  http_req_duration: ['p(50)<100', 'p(95)<300', 'p(99)<500'],
  http_req_failed: ['rate<0.01'],
};

export const STAGES_SMOKE = [
  { duration: '10s', target: 5 },
  { duration: '30s', target: 5 },
  { duration: '10s', target: 0 },
];

export const STAGES_LOAD = [
  { duration: '30s', target: 50 },
  { duration: '2m', target: 50 },
  { duration: '30s', target: 100 },
  { duration: '2m', target: 100 },
  { duration: '30s', target: 0 },
];

export const STAGES_STRESS = [
  { duration: '1m', target: 100 },
  { duration: '2m', target: 200 },
  { duration: '2m', target: 500 },
  { duration: '1m', target: 0 },
];

export const STAGES_SPIKE = [
  { duration: '10s', target: 10 },
  { duration: '5s', target: 500 },
  { duration: '30s', target: 500 },
  { duration: '10s', target: 10 },
  { duration: '30s', target: 0 },
];

import http from 'k6/http';
import { BASE_URL } from '../config.js';

export function registerUser(email, password, displayName) {
  const res = http.post(`${BASE_URL}/v1/auth/register`, JSON.stringify({
    email, password, displayName,
  }), { headers: { 'Content-Type': 'application/json' } });
  return JSON.parse(res.body);
}

export function loginUser(email, password) {
  const res = http.post(`${BASE_URL}/v1/auth/login`, JSON.stringify({
    email, password,
  }), { headers: { 'Content-Type': 'application/json' } });
  return JSON.parse(res.body);
}

export function refreshToken(token) {
  const res = http.post(`${BASE_URL}/v1/auth/refresh`, JSON.stringify({
    refreshToken: token,
  }), { headers: { 'Content-Type': 'application/json' } });
  return JSON.parse(res.body);
}

export function authHeaders(accessToken) {
  return { headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` } };
}

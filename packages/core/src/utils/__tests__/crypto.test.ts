import { describe, it, expect } from 'vitest';
import {
  generateToken,
  hashToken,
  generateUUID,
  encryptAES256GCM,
  decryptAES256GCM,
  timingSafeEqual,
} from '../crypto.js';

describe('crypto utilities', () => {
  describe('generateToken', () => {
    it('should return a URL-safe base64 string', () => {
      const token = generateToken(32);
      expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should generate different tokens each time', () => {
      const t1 = generateToken(32);
      const t2 = generateToken(32);
      expect(t1).not.toBe(t2);
    });

    it('should respect byte length parameter', () => {
      const token16 = generateToken(16);
      const token48 = generateToken(48);
      // base64url encoding: 4 chars per 3 bytes (no padding)
      expect(token48.length).toBeGreaterThan(token16.length);
    });
  });

  describe('hashToken', () => {
    it('should return a 64-character hex string (SHA-256)', () => {
      const hash = hashToken('test-token');
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should be deterministic', () => {
      const h1 = hashToken('same-input');
      const h2 = hashToken('same-input');
      expect(h1).toBe(h2);
    });

    it('should produce different hashes for different inputs', () => {
      const h1 = hashToken('input-a');
      const h2 = hashToken('input-b');
      expect(h1).not.toBe(h2);
    });
  });

  describe('generateUUID', () => {
    it('should return a valid UUID v4', () => {
      const uuid = generateUUID();
      expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    });

    it('should generate unique values', () => {
      const uuids = new Set(Array.from({ length: 100 }, () => generateUUID()));
      expect(uuids.size).toBe(100);
    });
  });

  describe('AES-256-GCM encryption', () => {
    const key = 'a'.repeat(64); // 32 bytes hex = 64 hex chars

    it('should encrypt and decrypt correctly', () => {
      const plaintext = 'my secret TOTP key';
      const encrypted = encryptAES256GCM(plaintext, key);
      const decrypted = decryptAES256GCM(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertext each time (random IV)', () => {
      const plaintext = 'same-plaintext';
      const e1 = encryptAES256GCM(plaintext, key);
      const e2 = encryptAES256GCM(plaintext, key);
      expect(e1).not.toBe(e2);
    });

    it('should throw on decryption with wrong key', () => {
      const plaintext = 'secret';
      const encrypted = encryptAES256GCM(plaintext, key);
      const wrongKey = 'b'.repeat(64);
      expect(() => decryptAES256GCM(encrypted, wrongKey)).toThrow();
    });

    it('should throw on tampered ciphertext', () => {
      const plaintext = 'secret';
      const encrypted = encryptAES256GCM(plaintext, key);
      const tampered = 'x' + encrypted.slice(1);
      expect(() => decryptAES256GCM(tampered, key)).toThrow();
    });

    it('should handle empty string', () => {
      const encrypted = encryptAES256GCM('', key);
      const decrypted = decryptAES256GCM(encrypted, key);
      expect(decrypted).toBe('');
    });

    it('should handle unicode content', () => {
      const plaintext = 'こんにちは世界 🔐';
      const encrypted = encryptAES256GCM(plaintext, key);
      const decrypted = decryptAES256GCM(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });
  });

  describe('timingSafeEqual', () => {
    it('should return true for equal strings', () => {
      expect(timingSafeEqual('abc', 'abc')).toBe(true);
    });

    it('should return false for different strings', () => {
      expect(timingSafeEqual('abc', 'def')).toBe(false);
    });

    it('should return false for different length strings', () => {
      expect(timingSafeEqual('short', 'longer-string')).toBe(false);
    });

    it('should return true for empty strings', () => {
      expect(timingSafeEqual('', '')).toBe(true);
    });
  });
});

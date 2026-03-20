import { randomBytes, randomUUID, createHash, createCipheriv, createDecipheriv, timingSafeEqual as nodeTimingSafeEqual } from 'node:crypto';

/**
 * Generate a cryptographically random URL-safe base64 token.
 */
export function generateToken(bytes: number = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/**
 * SHA-256 hash of a token. Returns lowercase hex string (64 chars).
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Generate a UUID v4.
 */
export function generateUUID(): string {
  return randomUUID();
}

/**
 * Encrypt plaintext with AES-256-GCM.
 * Key must be a 64-character hex string (32 bytes).
 * Returns: iv:authTag:ciphertext (all hex encoded).
 */
export function encryptAES256GCM(plaintext: string, keyHex: string): string {
  const key = Buffer.from(keyHex, 'hex');
  const iv = randomBytes(12); // 96-bit IV for GCM
  const cipher = createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Decrypt AES-256-GCM ciphertext.
 * Expects format: iv:authTag:ciphertext (all hex encoded).
 */
export function decryptAES256GCM(ciphertext: string, keyHex: string): string {
  const [ivHex, authTagHex, encryptedHex] = ciphertext.split(':');
  if (!ivHex || !authTagHex || encryptedHex === undefined) {
    throw new Error('Invalid ciphertext format');
  }

  const key = Buffer.from(keyHex, 'hex');
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Timing-safe string comparison to prevent timing attacks.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return nodeTimingSafeEqual(bufA, bufB);
}

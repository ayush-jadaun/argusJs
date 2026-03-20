import { createSign, createPrivateKey as nodeCreatePrivateKey } from 'node:crypto';

export function createPrivateKey(pem: string) {
  return nodeCreatePrivateKey(pem);
}

export function SignJWT(
  payload: Record<string, unknown>,
  privateKeyPem: string,
  keyId: string,
): string {
  const header = {
    alg: 'ES256',
    kid: keyId,
  };

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const key = createPrivateKey(privateKeyPem);
  const sign = createSign('SHA256');
  sign.update(signingInput);
  sign.end();

  const derSignature = sign.sign(key);
  // Convert DER-encoded ECDSA signature to raw r||s format for JWT
  const rawSignature = derToRaw(derSignature);
  const encodedSignature = rawSignature.toString('base64url');

  return `${signingInput}.${encodedSignature}`;
}

function derToRaw(derSignature: Buffer): Buffer {
  // DER format: 0x30 <len> 0x02 <rLen> <r> 0x02 <sLen> <s>
  let offset = 2; // skip 0x30 and total length
  if (derSignature[0] !== 0x30) {
    // If it's already raw, just return
    return derSignature;
  }

  // Read r
  offset++; // skip 0x02
  const rLen = derSignature[offset++];
  let r = derSignature.subarray(offset, offset + rLen);
  offset += rLen;

  // Read s
  offset++; // skip 0x02
  const sLen = derSignature[offset++];
  let s = derSignature.subarray(offset, offset + sLen);

  // Remove leading zero padding
  if (r.length === 33 && r[0] === 0) r = r.subarray(1);
  if (s.length === 33 && s[0] === 0) s = s.subarray(1);

  // Pad to 32 bytes if shorter
  const raw = Buffer.alloc(64);
  r.copy(raw, 32 - r.length);
  s.copy(raw, 64 - s.length);

  return raw;
}

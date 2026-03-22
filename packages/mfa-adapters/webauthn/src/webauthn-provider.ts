import { randomBytes } from 'node:crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoUint8Array } from '@simplewebauthn/server/helpers';
import type { MFAProvider, User, MFASetupData } from '@argusjs/core';

export interface WebAuthnConfig {
  rpName: string;
  rpId: string;
  origin: string;
  attestationType?: 'direct' | 'enterprise' | 'none';
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  backupCodeCount?: number;
}

export class WebAuthnProvider implements MFAProvider {
  public readonly name = 'webauthn';
  private readonly config: WebAuthnConfig;
  private readonly backupCodeCount: number;

  constructor(config: WebAuthnConfig) {
    this.config = config;
    this.backupCodeCount = config.backupCodeCount ?? 10;
  }

  async generateSecret(user: User): Promise<MFASetupData> {
    const options = await generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      userName: user.email,
      userDisplayName: user.displayName,
      userID: isoUint8Array.fromUTF8String(user.id),
      attestationType: this.config.attestationType ?? 'none',
      authenticatorSelection: this.config.authenticatorSelection ?? {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    const backupCodes = this.generateBackupCodes();

    return {
      secret: JSON.stringify(options),
      backupCodes,
      expiresIn: 300,
    };
  }

  async verifyCode(secret: string, code: string): Promise<boolean> {
    try {
      const data = JSON.parse(code);
      const expectedOptions = JSON.parse(secret);

      // Determine if this is a registration or authentication response
      if (data.response?.attestationObject) {
        // Registration response
        const verification = await verifyRegistrationResponse({
          response: data,
          expectedChallenge: expectedOptions.challenge,
          expectedOrigin: this.config.origin,
          expectedRPID: this.config.rpId,
        });
        return verification.verified;
      } else if (data.response?.authenticatorData) {
        // Authentication response
        const credential = expectedOptions.credential;
        if (!credential) {
          return false;
        }
        const verification = await verifyAuthenticationResponse({
          response: data,
          expectedChallenge: expectedOptions.challenge,
          expectedOrigin: this.config.origin,
          expectedRPID: this.config.rpId,
          credential: {
            id: credential.id,
            publicKey: new Uint8Array(credential.publicKey),
            counter: credential.counter,
            transports: credential.transports,
          },
        });
        return verification.verified;
      }

      return false;
    } catch {
      return false;
    }
  }

  generateBackupCodes(): string[] {
    const codes: Set<string> = new Set();
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

    while (codes.size < this.backupCodeCount) {
      const bytes = randomBytes(8);
      let code = '';
      for (let i = 0; i < 8; i++) {
        code += chars[bytes[i] % chars.length];
      }
      codes.add(`${code.slice(0, 4)}-${code.slice(4, 8)}`);
    }

    return Array.from(codes);
  }
}

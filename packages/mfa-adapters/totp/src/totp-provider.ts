import { randomBytes } from 'node:crypto';
import { authenticator } from 'otplib';
import type { MFAProvider, User, MFASetupData } from '@argusjs/core';
import { type TOTPConfig, DEFAULT_TOTP_CONFIG } from './config.js';

export class TOTPProvider implements MFAProvider {
  public readonly name = 'totp';
  private readonly config: Required<TOTPConfig>;

  constructor(config: TOTPConfig = {}) {
    this.config = { ...DEFAULT_TOTP_CONFIG, ...config };

    authenticator.options = {
      digits: this.config.digits,
      period: this.config.period,
      window: this.config.window,
    };
  }

  async generateSecret(user: User): Promise<MFASetupData> {
    const secret = authenticator.generateSecret();

    const qrCodeUrl = `otpauth://totp/${this.config.appName}:${user.email}?secret=${secret}&issuer=${this.config.appName}&digits=${this.config.digits}&period=${this.config.period}`;

    const backupCodes = this.generateBackupCodes();

    return {
      secret,
      qrCodeUrl,
      backupCodes,
      expiresIn: 600,
    };
  }

  async verifyCode(secret: string, code: string): Promise<boolean> {
    return authenticator.check(code, secret);
  }

  generateBackupCodes(): string[] {
    const codes: Set<string> = new Set();

    while (codes.size < this.config.backupCodeCount) {
      const bytes = randomBytes(4);
      const hex = bytes.toString('hex').toUpperCase().slice(0, 8);
      const code = `${hex.slice(0, 4)}-${hex.slice(4, 8)}`;
      codes.add(code);
    }

    return Array.from(codes);
  }
}

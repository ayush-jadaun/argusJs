import { randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import twilio from 'twilio';
import type { MFAProvider, User, MFASetupData } from '@argusjs/core';

export interface SMSConfig {
  accountSid: string;
  authToken: string;
  fromNumber: string;
  codeLength?: number;
  codeTTL?: number;
  backupCodeCount?: number;
}

export class SMSProvider implements MFAProvider {
  public readonly name = 'sms';
  private readonly config: SMSConfig;
  private readonly codeLength: number;
  private readonly codeTTL: number;
  private readonly backupCodeCount: number;
  private readonly client: ReturnType<typeof twilio>;

  constructor(config: SMSConfig) {
    this.config = config;
    this.codeLength = config.codeLength ?? 6;
    this.codeTTL = config.codeTTL ?? 300;
    this.backupCodeCount = config.backupCodeCount ?? 10;
    this.client = twilio(config.accountSid, config.authToken);
  }

  async generateSecret(user: User): Promise<MFASetupData> {
    const code = this.generateCode();
    const phone = user.metadata?.phone as string | undefined;

    if (phone) {
      await this.client.messages.create({
        body: `Your verification code is: ${code}`,
        from: this.config.fromNumber,
        to: phone,
      });
    }

    const backupCodes = this.generateBackupCodes();

    return {
      secret: code,
      backupCodes,
      expiresIn: this.codeTTL,
    };
  }

  async verifyCode(secret: string, code: string): Promise<boolean> {
    if (secret.length !== code.length) {
      return false;
    }

    try {
      const secretBuf = Buffer.from(secret, 'utf-8');
      const codeBuf = Buffer.from(code, 'utf-8');
      return timingSafeEqual(secretBuf, codeBuf);
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

  private generateCode(): string {
    const min = Math.pow(10, this.codeLength - 1);
    const max = Math.pow(10, this.codeLength);
    return randomInt(min, max).toString();
  }
}

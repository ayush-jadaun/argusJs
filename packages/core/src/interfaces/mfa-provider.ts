import type { User } from '../types/entities.js';
import type { MFASetupData } from '../types/responses.js';

export interface MFAProvider {
  name: string;
  init?(): Promise<void>;
  shutdown?(): Promise<void>;
  generateSecret(user: User): Promise<MFASetupData>;
  verifyCode(secret: string, code: string): Promise<boolean>;
  generateBackupCodes?(): string[];
}

export interface TOTPConfig {
  appName?: string;
  digits?: number;
  period?: number;
  window?: number;
  backupCodeCount?: number;
}

export const DEFAULT_TOTP_CONFIG: Required<TOTPConfig> = {
  appName: 'ArgusJS',
  digits: 6,
  period: 30,
  window: 1,
  backupCodeCount: 10,
};

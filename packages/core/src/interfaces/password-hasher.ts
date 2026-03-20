export interface PasswordHasher {
  name: string;
  hash(password: string): Promise<string>;
  verify(password: string, hash: string): Promise<boolean>;
  needsRehash?(hash: string): boolean;
}

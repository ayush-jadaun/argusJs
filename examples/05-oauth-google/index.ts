// OAuth login with Google
import { Argus } from '@argus/core';
import { MemoryDbAdapter } from '@argus/db-memory';
import { MemoryCacheAdapter } from '@argus/cache-memory';
import { Argon2Hasher } from '@argus/hash-argon2';
import { RS256TokenProvider } from '@argus/token-jwt-rs256';
import { MemoryEmailProvider } from '@argus/email-memory';
import { GoogleOAuth } from '@argus/oauth-google';

async function main() {
  const argus = new Argus({
    db: new MemoryDbAdapter(),
    cache: new MemoryCacheAdapter(),
    hasher: new Argon2Hasher({ memoryCost: 4096, timeCost: 2, parallelism: 1 }),
    token: new RS256TokenProvider({ issuer: 'my-app', audience: ['my-app'] }),
    email: new MemoryEmailProvider(),
    oauth: {
      google: new GoogleOAuth({
        clientId: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      }),
      // Add more providers:
      // github: new GitHubOAuth({ clientId: '...', clientSecret: '...' }),
      // apple: new AppleOAuth({ ... }),
    },
  });

  await argus.init();

  // 1. Generate OAuth URL (send user here)
  const authUrl = argus.oauth.getAuthorizationUrl('google', 'http://localhost:3000/callback', 'random-state');
  console.log('Redirect user to:', authUrl);

  // 2. After user authorizes, handle callback
  // const result = await argus.oauth.handleCallback('google', code, state);
  // result contains: { user, accessToken, refreshToken }

  console.log('\nSupported OAuth providers:');
  console.log('  - Google (@argus/oauth-google)');
  console.log('  - GitHub (@argus/oauth-github)');
  console.log('  - Apple (@argus/oauth-apple)');
  console.log('  - Microsoft (@argus/oauth-microsoft)');
  console.log('  - Discord (@argus/oauth-discord)');
  console.log('  - Custom OIDC (@argus/oauth-custom)');

  await argus.shutdown();
}

main().catch(console.error);

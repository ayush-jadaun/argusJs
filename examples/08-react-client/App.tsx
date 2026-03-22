// React app using @argusjs/client hooks
import { AuthProvider, useAuth, useSession } from '@argusjs/client/react';

function App() {
  return (
    <AuthProvider config={{ baseUrl: 'http://localhost:3100' }}>
      <AuthStatus />
    </AuthProvider>
  );
}

function AuthStatus() {
  const { user, isAuthenticated, isLoading, login, register, logout } = useAuth();
  const { sessions, fetchSessions, revokeSession } = useSession();

  if (isLoading) return <div>Loading...</div>;

  if (!isAuthenticated) {
    return (
      <div>
        <h1>Not logged in</h1>
        <button onClick={() => register({ email: 'demo@example.com', password: 'Demo123!@#', displayName: 'Demo' })}>
          Register
        </button>
        <button onClick={() => login('demo@example.com', 'Demo123!@#')}>
          Login
        </button>
      </div>
    );
  }

  return (
    <div>
      <h1>Welcome, {user?.displayName}</h1>
      <p>Email: {user?.email}</p>
      <p>MFA: {user?.mfaEnabled ? 'Enabled' : 'Disabled'}</p>
      <p>Roles: {user?.roles?.join(', ')}</p>
      <button onClick={() => logout()}>Logout</button>
      <button onClick={() => logout(true)}>Logout All Devices</button>
      <button onClick={fetchSessions}>View Sessions</button>
      {sessions.map(s => (
        <div key={s.id}>
          {s.ipAddress} — {s.userAgent} {s.isCurrent ? '(current)' : ''}
          {!s.isCurrent && <button onClick={() => revokeSession(s.id)}>Revoke</button>}
        </div>
      ))}
    </div>
  );
}

export default App;

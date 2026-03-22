import React, { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react';
import type { AuthResponse, UserResponse, MFAChallengeResponse, SessionResponse, MFASetupData } from '@argusjs/core';
import { ArgusClient } from '../argus-client.js';
import type { ArgusClientConfig } from '../argus-client.js';

interface AuthContextType {
  user: UserResponse | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<AuthResponse | MFAChallengeResponse>;
  register: (input: { email: string; password: string; displayName: string }) => Promise<AuthResponse>;
  logout: (allDevices?: boolean) => Promise<void>;
  verifyMFA: (input: { mfaToken: string; code: string; method: string }) => Promise<AuthResponse>;
  refreshUser: () => Promise<void>;
  client: ArgusClient;
}

const AuthContext = createContext<AuthContextType | null>(null);

export interface AuthProviderProps {
  config: ArgusClientConfig;
  children: React.ReactNode;
}

export function AuthProvider({ config, children }: AuthProviderProps) {
  const clientRef = useRef(new ArgusClient(config));
  const [user, setUser] = useState<UserResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const client = clientRef.current;

  const refreshUser = useCallback(async () => {
    try {
      if (client.isAuthenticated()) {
        const profile = await client.getProfile();
        setUser(profile);
      }
    } catch {
      setUser(null);
    }
  }, [client]);

  useEffect(() => {
    refreshUser().finally(() => setIsLoading(false));
  }, [refreshUser]);

  const login = useCallback(async (email: string, password: string) => {
    const res = await client.login(email, password);
    if ('accessToken' in res) {
      await refreshUser();
    }
    return res;
  }, [client, refreshUser]);

  const register = useCallback(async (input: { email: string; password: string; displayName: string }) => {
    const res = await client.register(input);
    await refreshUser();
    return res;
  }, [client, refreshUser]);

  const logout = useCallback(async (allDevices = false) => {
    await client.logout(allDevices);
    setUser(null);
  }, [client]);

  const verifyMFA = useCallback(async (input: { mfaToken: string; code: string; method: string }) => {
    const res = await client.verifyMFA(input);
    await refreshUser();
    return res;
  }, [client, refreshUser]);

  const value: AuthContextType = {
    user,
    isAuthenticated: user !== null,
    isLoading,
    login,
    register,
    logout,
    verifyMFA,
    refreshUser,
    client,
  };

  return React.createElement(AuthContext.Provider, { value }, children);
}

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

export function useUser(): UserResponse | null {
  return useAuth().user;
}

export function useSession() {
  const { client } = useAuth();
  const [sessions, setSessions] = useState<SessionResponse[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchSessions = useCallback(async () => {
    setLoading(true);
    try {
      const data = await client.getSessions();
      setSessions(data);
    } finally {
      setLoading(false);
    }
  }, [client]);

  const revokeSession = useCallback(async (id: string) => {
    await client.revokeSession(id);
    setSessions(prev => prev.filter(s => s.id !== id));
  }, [client]);

  return { sessions, loading, fetchSessions, revokeSession };
}

export function useMFA() {
  const { client } = useAuth();

  const setup = useCallback(async (method: string): Promise<MFASetupData> => {
    return client.setupMFA(method);
  }, [client]);

  const verifySetup = useCallback(async (method: string, code: string) => {
    await client.verifyMFASetup(method, code);
  }, [client]);

  const disable = useCallback(async (code: string) => {
    await client.disableMFA(code);
  }, [client]);

  return { setup, verifySetup, disable };
}

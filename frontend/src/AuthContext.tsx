import React, { createContext, useContext, useState, ReactNode, useEffect } from 'react';
import { API_URL } from './config';

interface User {
  id: string;
  email: string;
  role: string;
}

interface AuthContextType {
  user: User | null;
  accessToken: string | null;
  login: (user: User, token: string) => void;
  logout: () => void;
  setAccessToken: (token: string) => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [accessToken, setAccessTokenState] = useState<string | null>(null);
  
  // A real app would persist user profile in localStorage and token in memory
  useEffect(() => {
    const savedUser = localStorage.getItem('aegix_user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
  }, []);

  const login = (u: User, token: string) => {
    setUser(u);
    setAccessTokenState(token);
    localStorage.setItem('aegix_user', JSON.stringify(u));
  };

  const logout = () => {
    setUser(null);
    setAccessTokenState(null);
    localStorage.removeItem('aegix_user');
    // Call the logout endpoint to clear the HTTP-only cookie
    fetch(`${API_URL}/auth/logout`, { method: 'POST' }).catch(() => {});
  };

  return (
    <AuthContext.Provider value={{ user, accessToken, login, logout, setAccessToken: setAccessTokenState }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
};

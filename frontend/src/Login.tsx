import React, { useState, useEffect } from 'react';
import { useAuth } from './AuthContext';
import { ShieldAlert, Loader2 } from 'lucide-react';
import { API_URL } from './config';

export const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [isCheckingOAuth, setIsCheckingOAuth] = useState(true);
  const { login } = useAuth();

  useEffect(() => {
    // Attempt to silently log in if returning from OAuth (valid HTTP-only cookie)
    fetch(`${API_URL}/auth/refresh`, { method: 'POST', credentials: 'include' })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(data => {
        if (data.user && data.access_token) {
          login(data.user, data.access_token);
        }
      })
      .catch(() => {
        setIsCheckingOAuth(false);
      });
  }, [login]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    try {
      const endpoint = isRegistering ? `${API_URL}/auth/register` : `${API_URL}/auth/login`;
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        credentials: 'include'
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || (isRegistering ? 'Registration failed' : 'Invalid credentials'));
      }

      if (isRegistering) {
        setSuccess('Registration successful! You can now log in.');
        setIsRegistering(false);
        setPassword('');
      } else {
        const data = await res.json();
        login(data.user, data.access_token);
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  if (isCheckingOAuth) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--bg-dark)',
      }}>
        <Loader2 className="animate-spin" size={32} color="var(--neon-cyan)" />
      </div>
    );
  }

  return (
    <div className="app-layout" style={{ justifyContent: 'center', alignItems: 'center' }}>
      <div className="glass-card" style={{ width: '400px', padding: '2rem', display: 'flex', flexDirection: 'column' }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <ShieldAlert size={48} style={{ color: 'var(--neon-cyan)', margin: '0 auto' }} />
          <h1 style={{ marginTop: '1rem', fontSize: '1.5rem', color: 'var(--text-primary)' }}>
            {isRegistering ? 'AEGIX Registration' : 'AEGIX Authentication'}
          </h1>
          <p style={{ color: 'var(--text-muted)' }}>
            {isRegistering ? 'Create an admin account to start' : 'Sign in to access the security dashboard'}
          </p>
        </div>
        
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--text-secondary)', fontSize: '14px' }}>Email</label>
            <input 
              type="email" 
              value={email} 
              onChange={e => setEmail(e.target.value)}
              className="text-input" 
              style={{ width: '100%' }}
              required 
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--text-secondary)', fontSize: '14px' }}>Password</label>
            <input 
              type="password" 
              value={password} 
              onChange={e => setPassword(e.target.value)}
              className="text-input" 
              style={{ width: '100%' }}
              required 
            />
          </div>
          {error && <div className="dispatch-failed" style={{ marginTop: '0.5rem' }}>{error}</div>}
          {success && <div className="dispatch-success" style={{ marginTop: '0.5rem', color: 'var(--neon-green)' }}>{success}</div>}
          
          <button type="submit" className="btn-cyan" style={{ marginTop: '1.5rem', width: '100%', justifyContent: 'center' }}>
            {isRegistering ? 'CREATE ACCOUNT' : 'AUTHENTICATE'}
          </button>
        </form>

        <div style={{ display: 'flex', alignItems: 'center', margin: '2rem 0 1rem 0' }}>
          <div style={{ flex: 1, height: '1px', backgroundColor: 'var(--border-color)' }}></div>
          <span style={{ padding: '0 1rem', color: 'var(--text-muted)', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '1px' }}>Or continue with</span>
          <div style={{ flex: 1, height: '1px', backgroundColor: 'var(--border-color)' }}></div>
        </div>

        <div style={{ display: 'flex', gap: '1rem' }}>
          <button 
            type="button" 
            className="btn-outline" 
            style={{ flex: 1, justifyContent: 'center', backgroundColor: '#18181b', color: 'var(--text-primary)', borderColor: 'var(--border-color)' }}
            onClick={() => window.location.href = `${API_URL}/auth/github/login`}
          >
            GitHub
          </button>
          <button 
            type="button" 
            className="btn-outline" 
            style={{ flex: 1, justifyContent: 'center', backgroundColor: '#ffffff', color: '#000000', borderColor: '#ffffff' }}
            onClick={() => window.location.href = `${API_URL}/auth/google/login`}
          >
            Google
          </button>
        </div>

        <div style={{ marginTop: '2rem', textAlign: 'center' }}>
          <button 
            type="button" 
            className="btn-outline" 
            style={{ fontSize: '12px', border: 'none', background: 'none', color: 'var(--neon-cyan)', cursor: 'pointer' }}
            onClick={() => {
              setIsRegistering(!isRegistering);
              setError('');
              setSuccess('');
            }}
          >
            {isRegistering ? 'Already have an account? Sign In' : "Don't have an account? Sign Up"}
          </button>
        </div>
      </div>
    </div>
  );
}

import React, { useState, useEffect } from 'react';
import './App.css';
import { Dashboard } from './Dashboard';

function App() {
  const [apiStatus, setApiStatus] = useState('connecting');

  useEffect(() => {
    // Check API health
    fetch('http://localhost:8000/')
      .then(() => setApiStatus('online'))
      .catch(() => setApiStatus('offline'));
  }, []);

  return (
    <div className="app">
      <header className="app-header">
        <h1>🛡️ AI Bouncer + Kernel Guard</h1>
        <div className="status-badge" data-status={apiStatus}>
          {apiStatus === 'online' ? '🟢 Online' : '🔴 Offline'}
        </div>
      </header>
      <main className="app-main">
        {apiStatus === 'online' ? (
          <Dashboard />
        ) : (
          <div className="error-message">
            <h2>⚠️ Backend Offline</h2>
            <p>Ensure the backend is running: <code>python backend/app.py</code></p>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;

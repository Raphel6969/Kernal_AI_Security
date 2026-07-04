let getAccessToken: () => string | null = () => null;
let setAccessToken: (token: string) => void = () => {};

export const injectAuth = (get: () => string | null, set: (token: string) => void) => {
  getAccessToken = get;
  setAccessToken = set;
};

const API_URL = 'http://localhost:8000/api';

// fetchWithAuth wraps the native fetch, adding the Bearer token and handling silent refresh.
export const fetchWithAuth = async (url: string, options: RequestInit = {}): Promise<Response> => {
  let token = getAccessToken();
  
  const headers = new Headers(options.headers);
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  let response = await fetch(url, { ...options, headers });

  if (response.status === 401) {
    // Attempt silent refresh
    try {
      const refreshRes = await fetch(`${API_URL}/auth/refresh`, {
        method: 'POST',
        // Credentials 'include' ensures the HTTP-only refresh_token cookie is sent
        credentials: 'include' 
      });

      if (refreshRes.ok) {
        const data = await refreshRes.json();
        setAccessToken(data.access_token);
        
        // Retry original request
        headers.set('Authorization', `Bearer ${data.access_token}`);
        response = await fetch(url, { ...options, headers });
      } else {
        // Refresh failed, force logout (in a real app we'd dispatch a logout event)
        window.location.href = '/login';
      }
    } catch (e) {
      window.location.href = '/login';
    }
  }

  return response;
};

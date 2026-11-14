/**
 * RatchetChat - Client REST API Service
 */

const API = (function () {
  let authToken = null;

  function setToken(token) {
    authToken = token;
    if (typeof window !== 'undefined' && window.sessionStorage) {
      if (token) {
        window.sessionStorage.setItem('ratchetchat_token', token);
      } else {
        window.sessionStorage.removeItem('ratchetchat_token');
      }
    }
  }

  function getToken() {
    if (!authToken && typeof window !== 'undefined' && window.sessionStorage) {
      authToken = window.sessionStorage.getItem('ratchetchat_token');
    }
    return authToken;
  }

  async function request(endpoint, options = {}) {
    const headers = options.headers || {};
    headers['Content-Type'] = 'application/json';

    const token = getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(endpoint, {
      ...options,
      headers,
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const errorMsg = data.error || `HTTP error ${response.status}`;
      const err = new Error(errorMsg);
      err.status = response.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  return {
    setToken,
    getToken,

    // Auth
    register: (username, password) => request('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

    login: (username, password) => request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

    getUsers: () => request('/api/auth/users'),
    getMe: () => request('/api/auth/me'),

    // Prekeys
    publishPrekeys: (prekeyBundle) => request('/api/prekeys/publish', {
      method: 'POST',
      body: JSON.stringify(prekeyBundle),
    }),

    fetchPrekeyBundle: (username) => request(`/api/prekeys/${username}`),
    getOpkCount: (username) => request(`/api/prekeys/count/${username}`),

    // Messages
    sendOfflineMessage: (recipient, payload) => request('/api/messages/send', {
      method: 'POST',
      body: JSON.stringify({ recipient, payload }),
    }),

    fetchPendingMessages: () => request('/api/messages/pending'),

    // Admin / Attack Lab
    getRelayInspector: () => request('/api/admin/relay-inspector'),
    getDatabaseDump: () => request('/api/admin/database-dump'),
    toggleMitm: (settings) => request('/api/admin/mitm-toggle', {
      method: 'POST',
      body: JSON.stringify(settings),
    }),
    getSystemStats: () => request('/api/admin/system-stats'),
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = API;
}

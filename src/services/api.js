/**
 * Sentinel AI Gateway API Client
 * Centralized service module for communicating with the Python FastAPI backend.
 */

const DEFAULT_TIMEOUT_MS = 10000;

// Read API Base URL from localStorage (if customized in Settings) or environment variable
export function getApiBaseUrl() {
  const customUrl = localStorage.getItem('sentinel_api_base_url');
  if (customUrl && customUrl.trim() !== '') {
    return customUrl.trim().replace(/\/+$/, '');
  }
  return (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '');
}

export function setApiBaseUrl(url) {
  if (!url || url.trim() === '') {
    localStorage.removeItem('sentinel_api_base_url');
  } else {
    localStorage.setItem('sentinel_api_base_url', url.trim().replace(/\/+$/, ''));
  }
}

/**
 * Resilient fetch wrapper with timeout and structured error responses
 */
async function apiRequest(endpoint, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const baseUrl = getApiBaseUrl();
  const url = `${baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  const defaultHeaders = {
    'Accept': 'application/json',
  };

  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    defaultHeaders['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }

  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers,
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    let data = null;
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      try {
        data = await response.json();
      } catch (jsonErr) {
        throw new Error('Invalid JSON response received from backend gateway.');
      }
    } else {
      const text = await response.text();
      data = { raw: text };
    }

    if (!response.ok) {
      const errorMsg = data?.detail || data?.message || `Gateway returned HTTP ${response.status}: ${response.statusText}`;
      const err = new Error(errorMsg);
      err.status = response.status;
      err.data = data;
      throw err;
    }

    return {
      success: true,
      data,
      status: response.status,
    };
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      const timeoutErr = new Error(`Connection timed out after ${timeoutMs}ms. Backend gateway is unresponsive.`);
      timeoutErr.isTimeout = true;
      throw timeoutErr;
    }
    throw error;
  }
}

/**
 * GET /health
 * Check backend gateway health status and latency
 */
export async function checkHealth() {
  const startTime = performance.now();
  try {
    const res = await apiRequest('/health', { method: 'GET' }, 5000);
    const latency = Math.round(performance.now() - startTime);
    return {
      connected: true,
      latency,
      status: res.data?.status || 'ok',
      version: res.data?.version || '1.0.0',
      data: res.data,
      url: getApiBaseUrl(),
    };
  } catch (err) {
    const latency = Math.round(performance.now() - startTime);
    return {
      connected: false,
      latency,
      error: err.message || 'Cannot reach Sentinel AI Gateway',
      url: getApiBaseUrl(),
    };
  }
}

/**
 * POST /scan
 * Scan a prompt for sensitive data, credentials, and prompt injection
 * @param {string} prompt - The raw user prompt
 */
export async function scanPrompt(prompt) {
  return await apiRequest('/scan', {
    method: 'POST',
    body: { prompt },
  });
}

/**
 * POST /chat
 * Submit a prompt through the security gateway to the AI model
 * @param {string} prompt - The user prompt
 * @param {string} model - Optional model identifier
 */
export async function submitChat(prompt, model = 'gpt-4o-security-proxy') {
  return await apiRequest('/chat', {
    method: 'POST',
    body: { prompt, model },
  });
}

/**
 * GET /events
 * Retrieve security event audit metadata
 */
export async function getEvents() {
  return await apiRequest('/events', {
    method: 'GET',
  });
}

/**
 * DELETE /events
 * Clear all security event metadata
 */
export async function clearEvents() {
  return await apiRequest('/events', {
    method: 'DELETE',
  });
}

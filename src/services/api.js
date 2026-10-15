/**
 * Sentinel AI Gateway API Client
 * Centralized service module for communicating with the Python FastAPI backend.
 */

const DEFAULT_TIMEOUT_MS = 15000;

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
      error: err.message || 'Cannot reach Leak-Sheild-AI Gateway',
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
export async function submitChat(prompt, model = 'llama3.2:3b') {
  return await apiRequest('/chat', {
    method: 'POST',
    body: { prompt, model },
  });
}

/**
 * GET /events
 * Retrieve real security event audit metadata
 */
export async function getEvents(limit = 100, offset = 0, decision = null) {
  let endpoint = `/events?limit=${limit}&offset=${offset}`;
  if (decision && decision !== 'ALL') {
    endpoint += `&decision=${encodeURIComponent(decision)}`;
  }
  return await apiRequest(endpoint, {
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

/**
 * GET /policies
 * Retrieve current server-side security policies
 */
export async function getPolicies() {
  return await apiRequest('/policies', {
    method: 'GET',
  });
}

/**
 * PUT /policies
 * Update server-side security policies
 */
export async function updatePolicies(policies) {
  return await apiRequest('/policies', {
    method: 'PUT',
    body: policies,
  });
}

/**
 * GET /metrics
 * Retrieve operational statistics computed from real SQLite events
 */
export async function getMetrics() {
  return await apiRequest('/metrics', {
    method: 'GET',
  });
}

/**
 * GET /events/search
 * Natural language semantic search across security audit logs
 * @param {string} query - The semantic query (e.g. "password leak", "cloud secrets")
 * @param {number} minScore - Minimum cosine similarity threshold (0.0 to 1.0)
 * @param {number} limit - Maximum events to return
 */
export async function searchEventsSemantic(query, minScore = 0.1, limit = 50) {
  const endpoint = `/events/search?query=${encodeURIComponent(query)}&min_score=${minScore}&limit=${limit}`;
  return await apiRequest(endpoint, {
    method: 'GET',
  });
}

/**
 * POST /scan/image
 * Scan an image provided as a Base64 string / Data URI for EXIF GPS leaks and secrets
 * @param {string} imageBase64 - Base64 or Data URI string of the image
 * @param {string} filename - Filename identifier
 */
export async function scanImage(imageBase64, filename = 'image.png') {
  return await apiRequest('/scan/image', {
    method: 'POST',
    body: {
      image_base64: imageBase64,
      filename,
    },
  });
}

/**
 * POST /scan/image/upload
 * Scan an image file via multipart/form-data upload
 * @param {File} file - Browser File object
 */
export async function scanImageFile(file) {
  const formData = new FormData();
  formData.append('file', file, file.name);

  return await apiRequest('/scan/image/upload', {
    method: 'POST',
    body: formData,
  });
}

/**
 * POST /scan/file
 * Scan an uploaded document (.pdf, .docx, .csv, .json, .txt, .md) for sensitive data and injection attacks
 * @param {File} file - Browser File object
 */
export async function scanDocumentFile(file) {
  const formData = new FormData();
  formData.append('file', file, file.name);

  return await apiRequest('/scan/file', {
    method: 'POST',
    body: formData,
  }, 30000);
}

/**
 * POST /redact/file
 * Redact sensitive data from document file (.pdf, .docx, .csv, .json, .txt, .md)
 * @param {File} file - Browser File object
 */
export async function redactDocumentFile(file) {
  const formData = new FormData();
  formData.append('file', file, file.name);

  return await apiRequest('/redact/file', {
    method: 'POST',
    body: formData,
  }, 30000);
}

/**
 * POST /redact/image
 * Redact visible OCR sensitive text and strip EXIF metadata from base64 image
 * @param {string} imageBase64 - Base64 or Data URI string
 * @param {string} filename - Filename identifier
 */
export async function redactImage(imageBase64, filename = 'image.png') {
  return await apiRequest('/redact/image', {
    method: 'POST',
    body: {
      image_base64: imageBase64,
      filename,
    },
  }, 30000);
}

/**
 * POST /redact/image/upload
 * Redact image via multipart/form-data upload
 * @param {File} file - Browser File object
 */
export async function redactImageFile(file) {
  const formData = new FormData();
  formData.append('file', file, file.name);

  return await apiRequest('/redact/image/upload', {
    method: 'POST',
    body: formData,
  }, 30000);
}

/**
 * Get direct verified download URL for a redacted file
 * @param {string} fileId - The secure red_<token> file ID
 */
export function getRedactedDownloadUrl(fileId) {
  const baseUrl = getApiBaseUrl();
  return `${baseUrl}/redact/download/${fileId}`;
}

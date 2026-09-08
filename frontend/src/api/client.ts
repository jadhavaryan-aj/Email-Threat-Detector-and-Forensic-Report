import axios from "axios";

const API_KEY_STORAGE_KEY = "backendApiKey";

export const apiClient = axios.create({
  baseURL: "/api",
});

// BACKEND_API_KEY is optional server-side (see backend/app/auth.py) — most
// local/demo setups run with no key and every request below is a no-op.
apiClient.interceptors.request.use((config) => {
  const key = localStorage.getItem(API_KEY_STORAGE_KEY);
  if (key) {
    config.headers.set("X-API-Key", key);
  }
  return config;
});

// Only prompt once per burst of 401s (e.g. several queries firing on page
// load) rather than stacking native prompts on top of each other.
let promptInFlight = false;

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !promptInFlight) {
      promptInFlight = true;
      const key = window.prompt("This backend requires an API key. Enter it to continue:");
      promptInFlight = false;
      if (key) {
        localStorage.setItem(API_KEY_STORAGE_KEY, key);
        window.location.reload();
      }
    }
    return Promise.reject(error);
  },
);

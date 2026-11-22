import { csrfHeaders } from "./csrf.js";
export async function apiFetch(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin) {
    throw new Error("Потрібна адреса цього застосунку.");
  }
  const method = (options.method ?? 'GET').toUpperCase();
  const protectedRequest = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) &&
    !['/api/auth/login', '/api/auth/register'].includes(url.pathname);
  const extra = protectedRequest ? await csrfHeaders() : {};
  return fetch(url, { ...options, headers: { ...options.headers, ...extra }, credentials: "same-origin" });
}

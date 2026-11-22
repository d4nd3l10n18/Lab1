let token = null;
export function clearCsrfToken() { token = null; }
export async function csrfHeaders() {
  if (!token) {
    const response = await fetch('/api/auth/csrf-token', { credentials: 'same-origin', cache: 'no-store' });
    if (!response.ok) throw new Error(`Cannot get antiforgery token: ${response.status}`);
    const body = await response.json();
    if (typeof body.token !== 'string' || !body.token) throw new Error('Empty antiforgery token');
    token = body.token;
  }
  return { 'X-SecureLab-CSRF': token };
}

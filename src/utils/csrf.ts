// src/utils/csrf.ts

import { getCookie } from '../sessions';
import { readJson } from './http';

export function makeCsrfToken(): string {
	const b = crypto.getRandomValues(new Uint8Array(16));
	return Array.from(b)
		.map((x) => x.toString(16).padStart(2, '0'))
		.join('');
}

export function csrfCookie(token: string): string {
	return `__Host-csrf=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600; Priority=Medium`;
}

export function sameOrigin(request: Request, publicBaseUrl: string): boolean {
	const origin = request.headers.get('origin');
	if (!origin) return false;

	try {
		return new URL(origin).origin === new URL(publicBaseUrl).origin;
	} catch {
		return false;
	}
}

type Obj = Record<string, unknown>;

function getStringField(obj: Obj, key: string): string | null {
	const v = obj[key];
	return typeof v === 'string' ? v : null;
}

export async function requireCsrfJson<T extends Obj>(request: Request): Promise<{ ok: true; body: T } | { ok: false; code: string }> {
	const parsed = await readJson<T>(request);
	if (!parsed.ok) return parsed;

	const cookieToken = getCookie(request, '__Host-csrf');
	if (!cookieToken) return { ok: false, code: 'csrf_missing' };

	const provided = getStringField(parsed.body, 'csrf');
	if (!provided || provided.length !== 32) return { ok: false, code: 'csrf_missing' };
	if (provided !== cookieToken) return { ok: false, code: 'csrf_invalid' };

	return parsed;
}

import type { ProjectConfig, Session } from '../types';

/**
 * Attaches a signed user payload to the request headers.
 *
 * @export
 * @async
 * @param {Headers} headers
 * @param {Session} session
 * @param {ProjectConfig} cfg
 * @param {Env} env
 * @returns {Promise<void>}
 */
export async function attachSignedUser(headers: Headers, session: Session, cfg: ProjectConfig, env: Env): Promise<void> {
	const name = cfg.propagation.headerName ?? 'X-User';
	const sigName = cfg.propagation.sigHeaderName ?? 'X-User-Sig';
	const secret = env[cfg.propagation.hmacSecretEnv];
	if (!secret) throw new Error('Missing HMAC secret');

	const payloadObj = { userId: session.userId, email: session.email, ts: Math.floor(Date.now() / 1000) };
	const json = JSON.stringify(payloadObj);
	const payload = btoa(String.fromCharCode(...new Uint8Array(new TextEncoder().encode(json))));
	const sig = await signHmac(payload, secret as string);

	headers.set(name, payload);
	headers.set(sigName, sig);
}

/**
 * Removes the user payload from the request headers.
 *
 * @export
 * @param {Headers} headers
 * @param {ProjectConfig} cfg
 */
export function stripUser(headers: Headers, cfg: ProjectConfig): void {
	headers.delete(cfg.propagation.headerName ?? 'X-User');
	headers.delete(cfg.propagation.sigHeaderName ?? 'X-User-Sig');
}

/**
 * Signs a payload using HMAC with the given secret.
 *
 * @async
 * @param {string} payload
 * @param {string} secret
 * @returns {Promise<string>}
 */
async function signHmac(payload: string, secret: string): Promise<string> {
	const enc = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
	const bytes = new Uint8Array(sigBuf);
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

// src/utils/propagation.ts
import type { ProjectConfig, Session } from '../types';

export type PropagatedUserPayload = {
	userId: string;
	email: string;
	systemRoles: string[];
	ts: number;
};

/**
 * Attaches a signed user payload to the request headers.
 */
export async function attachSignedUser(headers: Headers, session: Session, cfg: ProjectConfig, env: Env): Promise<void> {
	const name = cfg.propagation.headerName ?? 'X-User';
	const sigName = cfg.propagation.sigHeaderName ?? 'X-User-Sig';
	const secret = env[cfg.propagation.hmacSecretEnv];
	if (!secret) throw new Error('Missing HMAC secret');

	const payloadObj: PropagatedUserPayload = {
		userId: session.userId,
		email: session.email,
		systemRoles: session.systemRoles,
		ts: Math.floor(Date.now() / 1000),
	};

	const payload = encodeJsonToBase64(payloadObj);
	const sig = await signHmac(payload, secret);

	headers.set(name, payload);
	headers.set(sigName, sig);
}

/**
 * Removes the user payload from the request headers.
 */
export function stripUser(headers: Headers, cfg: ProjectConfig): void {
	headers.delete(cfg.propagation.headerName ?? 'X-User');
	headers.delete(cfg.propagation.sigHeaderName ?? 'X-User-Sig');
}

/**
 * Encode an object as base64(JSON).
 * (Used by gateway to create X-User; reused by verifiers to decode.)
 */
export function encodeJsonToBase64(value: unknown): string {
	const json = JSON.stringify(value);
	const bytes = new Uint8Array(new TextEncoder().encode(json));
	return btoa(String.fromCharCode(...bytes));
}

/**
 * Decode base64(JSON) into a JS value.
 */
export function decodeJsonFromBase64<T = unknown>(payloadB64: string): T {
	const bin = atob(payloadB64);
	const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
	const json = new TextDecoder().decode(bytes);
	return JSON.parse(json) as T;
}

/**
 * Signs a payload using HMAC with the given secret.
 * Returns base64url.
 */
export async function signHmac(payload: string, secret: string): Promise<string> {
	const enc = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
	const bytes = new Uint8Array(sigBuf);
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

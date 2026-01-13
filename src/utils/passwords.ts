// src/utils/passwords.ts

type StoredHash = {
	alg: 'pbkdf2';
	hash: 'SHA-256' | 'SHA-512';
	iter: number;
	dkLen: number;
	saltB64u: string;
	dkB64u: string;
};

const DEFAULT_PARAMS = {
	hash: 'SHA-256' as const,
	iter: 600_000,
	dkLen: 32,
};

let cachedFake: string | null = null;

export function getFakeStoredHash(): string {
	// Best-effort cache per isolate; fine if it resets on cold start.
	if (cachedFake) return cachedFake;

	const salt = crypto.getRandomValues(new Uint8Array(32));
	const dk = crypto.getRandomValues(new Uint8Array(32)); // dkLen must match your DEFAULT_PARAMS.dkLen

	const saltB64u = b64urlEncodeBytes(salt);
	const dkB64u = b64urlEncodeBytes(dk);

	cachedFake = `pbkdf2$SHA-256$600000$32$${saltB64u}$${dkB64u}`;
	return cachedFake;
}

/**
 * PASSWORD_PEPPERS format:
 *	"pepper_v2,pepper_v1" (newest first)
 */
export function getPeppers(env: Env, pepperEnv: string = 'PASSWORD_PEPPERS'): string[] {
	const raw = (env[pepperEnv] ?? '').trim();
	if (!raw) return [];
	return raw
		.split(',')
		.map((s) => s.trim())
		.filter((s) => s.length > 0);
}

/**
 * Stored format:
 *	pbkdf2$SHA-256$600000$32$<saltB64u>$<dkB64u>
 */
export async function hashPassword(
	password: string,
	options?: {
		pepper?: string;
		params?: Partial<typeof DEFAULT_PARAMS>;
	},
): Promise<string> {
	const salt = crypto.getRandomValues(new Uint8Array(32));
	const saltB64u = b64urlEncodeBytes(salt);

	const params = { ...DEFAULT_PARAMS, ...options?.params };

	const dk = await deriveKeyBytes(
		password,
		{
			alg: 'pbkdf2',
			hash: params.hash,
			iter: params.iter,
			dkLen: params.dkLen,
			saltB64u,
			dkB64u: '',
		},
		options?.pepper,
	);

	const dkB64u = b64urlEncodeBytes(dk);
	return `pbkdf2$${params.hash}$${params.iter}$${params.dkLen}$${saltB64u}$${dkB64u}`;
}

export async function verifyPassword(password: string, stored: string, pepper?: string): Promise<boolean> {
	const parsed = parseStored(stored);
	if (!parsed) return false;

	const dk = await deriveKeyBytes(password, parsed, pepper);
	const expected = b64urlDecodeBytes(parsed.dkB64u);
	return timingSafeEqualBytes(dk, expected);
}

/**
 * Verifies using multiple peppers (newest->oldest). Returns which matched.
 * If no peppers configured, treats as "no pepper".
 */
export async function verifyPasswordWithPepperRotation(
	password: string,
	stored: string,
	peppers: string[],
): Promise<{ ok: true; usedPepperIndex: number } | { ok: false }> {
	if (!peppers.length) {
		const ok = await verifyPassword(password, stored, undefined);
		return ok ? { ok: true, usedPepperIndex: -1 } : { ok: false };
	}

	for (let i = 0; i < peppers.length; i++) {
		if (await verifyPassword(password, stored, peppers[i])) {
			return { ok: true, usedPepperIndex: i };
		}
	}
	return { ok: false };
}

export function needsRehash(stored: string, desired?: Partial<typeof DEFAULT_PARAMS>): boolean {
	const parsed = parseStored(stored);
	if (!parsed) return true;

	const target = { ...DEFAULT_PARAMS, ...desired };
	return parsed.hash !== target.hash || parsed.iter !== target.iter || parsed.dkLen !== target.dkLen;
}

/* ----------------------------- internals ----------------------------- */

async function deriveKeyBytes(password: string, parsed: StoredHash, pepper?: string): Promise<Uint8Array> {
	const pw = normalizePassword(password, pepper);

	const pwKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), { name: 'PBKDF2' }, false, ['deriveBits']);

	const salt = b64urlDecodeBytes(parsed.saltB64u);

	const bits = await crypto.subtle.deriveBits(
		{
			name: 'PBKDF2',
			hash: parsed.hash,
			salt,
			iterations: parsed.iter,
		},
		pwKey,
		parsed.dkLen * 8,
	);

	return new Uint8Array(bits);
}

function normalizePassword(password: string, pepper?: string): string {
	const p = password.normalize('NFC');
	return pepper ? `${pepper}\u0000${p}` : p;
}

function parseStored(stored: string): StoredHash | null {
	const parts = stored.split('$');
	if (parts.length !== 6) return null;

	const [alg, hash, iterStr, dkLenStr, saltB64u, dkB64u] = parts;

	if (alg !== 'pbkdf2') return null;
	if (hash !== 'SHA-256' && hash !== 'SHA-512') return null;

	const iter = Number(iterStr);
	const dkLen = Number(dkLenStr);
	if (!Number.isFinite(iter) || iter <= 0) return null;
	if (!Number.isFinite(dkLen) || dkLen <= 0) return null;

	return { alg: 'pbkdf2', hash, iter, dkLen, saltB64u, dkB64u };
}

function b64urlEncodeBytes(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/g, '');
}

function b64urlDecodeBytes(b64u: string): Uint8Array {
	let b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
	const pad = b64.length % 4;
	if (pad) b64 += '='.repeat(4 - pad);

	const bin = atob(b64);
	return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let out = 0;
	for (let i = 0; i < a.length; i++) {
		out |= a[i] ^ b[i];
	}
	return out === 0;
}

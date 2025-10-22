import type { StateInfo, StateMode, StoredPkce } from '../types';

/**
 * Creates a new PKCE state.
 *
 * @export
 * @async
 * @returns {Promise<{ state: string; codeChallenge: string; verifier: string }>}
 */
export async function makePkceState(): Promise<{
	state: string;
	codeChallenge: string;
	verifier: string;
}> {
	const verBytes = crypto.getRandomValues(new Uint8Array(32));
	const verifier = Array.from(verBytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
	const state = crypto.randomUUID();
	const codeChallenge = await sha256Base64Url(verifier);
	return { state, codeChallenge, verifier };
}

/**
 * Saves a short-lived PKCE state to KV.
 *
 * @export
 * @async
 * @param {KVNamespace} kv
 * @param {string} state
 * @param {string} verifier
 * @param {number} ttlSec
 * @param {StateInfo} info
 * @returns {Promise<void>}
 */
export async function saveShortState(kv: KVNamespace, state: string, verifier: string, ttlSec: number, info: StateInfo): Promise<void> {
	const payload: StoredPkce = { v: verifier, i: info };
	await kv.put(`_pkce:${state}`, JSON.stringify(payload), { expirationTtl: ttlSec });
}

/**
 * Consumes a short-lived PKCE state from KV.
 *
 * @export
 * @async
 * @param {KVNamespace} kv
 * @param {string} stateParam
 * @returns {Promise<{ verifier: string; info: StateInfo }>}
 */
export async function consumeShortState(kv: KVNamespace, stateParam: string): Promise<{ verifier: string; info: StateInfo }> {
	const key = `_pkce:${stateParam}`;
	const raw = await kv.get(key);
	if (!raw) throw new Error('state expired');

	// Best-effort cleanup first to avoid reuse; errors ignored
	await kv.delete(key).catch(() => {});

	let parsed: StoredPkce | null = null;
	try {
		parsed = JSON.parse(raw) as StoredPkce;
	} catch {
		throw new Error('bad_state');
	}

	const verifier = parsed?.v;
	const info = parsed?.i ?? { mode: 'login' as StateMode };
	if (!verifier) throw new Error('bad_state');

	return { verifier, info };
}

/**
 * Computes the SHA-256 hash of the input and encodes it in base64url.
 *
 * @async
 * @param {string} input
 * @returns {Promise<string>}
 */
async function sha256Base64Url(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest('SHA-256', data);
	const b = String.fromCharCode(...new Uint8Array(digest));
	return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

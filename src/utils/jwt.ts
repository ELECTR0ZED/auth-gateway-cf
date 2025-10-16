// utils/jwt.ts
function b64urlBytes(b: Uint8Array): string {
	return btoa(String.fromCharCode(...b))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/g, "");
}

function b64urlEncodeUtf8(s: string): string {
	return b64urlBytes(new TextEncoder().encode(s));
}

function b64urlToBytes(u: string): Uint8Array {
	const b64 = u.replace(/-/g, "+").replace(/_/g, "/");
	const bin = atob(b64);
	return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function b64urlDecodeUtf8(u: string): string {
	return new TextDecoder().decode(b64urlToBytes(u));
}

export async function signJwtHS256(
	payload: Record<string, any>,
	secret?: string
): Promise<string> {
	if (!secret) {
		throw new Error("missing secret");
	}

	const header = b64urlEncodeUtf8(JSON.stringify({ alg: "HS256", typ: "JWT" }));
	const body = b64urlEncodeUtf8(JSON.stringify(payload));

	const enc = new TextEncoder();
	const key = await crypto.subtle.importKey(
		"raw",
		enc.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"]
	);

	const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(`${header}.${body}`));
	const sig = b64urlBytes(new Uint8Array(sigBuf));
	return `${header}.${body}.${sig}`;
}

export async function verifyJwtHS256(token: string, secret?: string): Promise<any> {
	if (!secret) {
		throw new Error("missing secret");
	}

	const [h, p, s] = token.split(".");
	if (!h || !p || !s) {
		throw new Error("bad jwt");
	}

	const enc = new TextEncoder();
	const key = await crypto.subtle.importKey(
		"raw",
		enc.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["verify"]
	);

	const ok = await crypto.subtle.verify("HMAC", key, b64urlToBytes(s), enc.encode(`${h}.${p}`));
	if (!ok) {
		throw new Error("bad sig");
	}

	const payload = JSON.parse(b64urlDecodeUtf8(p));
	const now = Math.floor(Date.now() / 1000);
	if (payload.exp && now >= payload.exp) {
		throw new Error("expired");
	}
	if (payload.nbf && now < payload.nbf) {
		throw new Error("nbf");
	}
	return payload;
}

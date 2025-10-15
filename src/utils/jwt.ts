export async function signJwtHS256(
	payload: Record<string, any>,
	secret?: string
): Promise<string> {
	if (!secret) {
		throw new Error("missing secret");
	}
	const enc = new TextEncoder();
	const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
	const body = b64url(JSON.stringify(payload));
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
	const enc = new TextEncoder();
	const [h, p, s] = token.split(".");
	if (!h || !p || !s) {
		throw new Error("bad jwt");
	}
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
	const payload = JSON.parse(
		atob(p.replace(/-/g, "+").replace(/_/g, "/"))
	);
	const now = Math.floor(Date.now() / 1000);
	if (payload.exp && now >= payload.exp) {
		throw new Error("expired");
	}
	if (payload.nbf && now < payload.nbf) {
		throw new Error("nbf");
	}
	return payload;
}

function b64url(s: string): string {
	return btoa(s)
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/g, "");
}

function b64urlBytes(b: Uint8Array): string {
	return b64url(String.fromCharCode(...b));
}

function b64urlToBytes(u: string): Uint8Array {
	const b64 = u.replace(/-/g, "+").replace(/_/g, "/");
	const bin = atob(b64);
	return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
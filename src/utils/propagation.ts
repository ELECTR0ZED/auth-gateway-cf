import type { ProjectConfig } from "../core/types";

export async function attachSignedUser(
	headers: Headers,
	session: any,
	cfg: ProjectConfig,
	env: any
) {
	const name = cfg.propagation.headerName ?? "X-User";
	const sigName = cfg.propagation.sigHeaderName ?? "X-User-Sig";
	const secret = env[cfg.propagation.hmacSecretEnv];
	if (!secret) throw new Error("Missing HMAC secret");

	const payload = btoa(JSON.stringify(session));
	const sig = await signHmac(payload, secret);

	headers.set(name, payload);
	headers.set(sigName, sig);
}

export function stripUser(headers: Headers, cfg: ProjectConfig) {
	headers.delete(cfg.propagation.headerName ?? "X-User");
	headers.delete(cfg.propagation.sigHeaderName ?? "X-User-Sig");
}

async function signHmac(payload: string, secret: string): Promise<string> {
	const enc = new TextEncoder();
	const key = await crypto.subtle.importKey(
		"raw",
		enc.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"]
	);
	const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
	const bytes = new Uint8Array(sigBuf);
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, ""); // base64url
}

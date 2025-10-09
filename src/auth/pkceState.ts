export async function makePkceState() {
  const verBytes = crypto.getRandomValues(new Uint8Array(32));
  const verifier = Array.from(verBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const state = crypto.randomUUID();
  const codeChallenge = await sha256Base64Url(verifier);
  return { state, codeChallenge, verifier };
}

export async function saveShortState(
  kv: KVNamespace,
  state: string,
  verifier: string,
  ttlSec: number
) {
  await kv.put(`_pkce:${state}`, verifier, { expirationTtl: ttlSec });
}

export async function consumeShortState(
  kv: KVNamespace,
  stateParam: string
): Promise<{ verifier: string; returnTo?: string }> {
  const parts = stateParam.split("::");
  const key = parts[0];
  const verifier = await kv.get(`_pkce:${key}`);
  if (!verifier) throw new Error("state expired");
  await kv.delete(`_pkce:${key}`);
  return { verifier, returnTo: parts[1] };
}

async function sha256Base64Url(input: string) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const b = String.fromCharCode(...new Uint8Array(digest));
  return btoa(b)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}
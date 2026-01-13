export function safeReturnTo(returnTo: string | undefined, publicBaseUrl: string): string | undefined {
	if (!returnTo) return undefined;

	// Allow only same-origin relative paths by default
	if (returnTo.startsWith('/')) return returnTo;

	// Optional: allow absolute URLs only if same origin
	try {
		const rt = new URL(returnTo);
		const pub = new URL(publicBaseUrl);
		if (rt.origin === pub.origin) {
			return rt.pathname + rt.search + rt.hash;
		}
	} catch {
		// ignore
	}

	return undefined;
}

import type { ProviderConfig } from "../core/types";
import { AuthProvider } from "./baseProvider";

export class GoogleProvider extends AuthProvider {
	id = "google" as const;

	protected getAuthorizeEndpoint(_: ProviderConfig): string {
		return "https://accounts.google.com/o/oauth2/v2/auth";
	}

	protected getTokenEndpoint(_: ProviderConfig): string {
		return "https://oauth2.googleapis.com/token";
	}

	protected getDefaultScope(cfg: ProviderConfig): string {
		// Keep provider-configurable if you pass a custom scope; else sane defaults
		return cfg.scope ?? "openid email profile";
	}

	// Google returns id_token; base handles parsing + normalize.
	// Optional: ensure we have userinfo fallback if needed.
	protected async fetchUserInfo(_: ProviderConfig, accessToken: string): Promise<{ claims: any }> {
		const r = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
			headers: { authorization: `Bearer ${accessToken}` },
		});
		if (!r.ok) throw new Error(`userinfo failed: ${r.status}`);
		return { claims: await r.json() };
	}
}

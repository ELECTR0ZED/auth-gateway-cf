import type { ProviderConfig } from "../core/types";
import { AuthProvider } from "./baseProvider";

/**
 * Microsoft Entra ID (Azure AD) OIDC provider (not B2C).
 * Requires cfg.tenant (e.g., "common", "organizations", or a tenant ID/GUID).
 */
export class MicrosoftEntraProvider extends AuthProvider {
	id = "entra" as const;

	protected getAuthorizeEndpoint(cfg: ProviderConfig): string {
		const tenant = cfg.tenant ?? "common";
		return `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`;
	}

	protected getTokenEndpoint(cfg: ProviderConfig): string {
		const tenant = cfg.tenant ?? "common";
		return `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
	}

	protected getDefaultScope(cfg: ProviderConfig): string {
		// email claim may appear as 'preferred_username' if email scope not granted
		return cfg.scope ?? "openid profile email";
	}

	// Most of the time we get an id_token; base handles parse+normalize.
	// If you prefer userinfo, you can set cfg.userInfoUrl = "https://graph.microsoft.com/oidc/userinfo"
	// and grant 'openid profile email' on the app registration + add Graph permissions if needed.
}

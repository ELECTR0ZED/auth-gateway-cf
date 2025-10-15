import type { ProviderConfig } from "../core/types";
import { AuthProvider } from "./baseProvider";

/**
 * Azure AD B2C provider:
 * - authorize: https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policy}/oauth2/v2.0/authorize
 * - token:     https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{policy}/oauth2/v2.0/token
 */
export class AzureB2CProvider extends AuthProvider {
	id = "azure_b2c" as const;

	protected getAuthorizeEndpoint(cfg: ProviderConfig): string {
		const tenant = cfg.tenant!;
		const policy = cfg.b2cPolicy!;
		return `https://${tenant}.b2clogin.com/${tenant}.onmicrosoft.com/${policy}/oauth2/v2.0/authorize`;
	}

	protected getTokenEndpoint(cfg: ProviderConfig): string {
		const tenant = cfg.tenant!;
		const policy = cfg.b2cPolicy!;
		return `https://${tenant}.b2clogin.com/${tenant}.onmicrosoft.com/${policy}/oauth2/v2.0/token`;
	}

	// Optional: override default scope for B2C (kept for clarity)
	protected getDefaultScope(cfg: ProviderConfig): string {
		return cfg.scope ?? "openid profile email offline_access";
	}

	// Optional: override normalize if you need special role mapping
	// protected normalize(claims: any): Session {
	//   const base = super.normalize(claims);
	//   // e.g., map custom attributes
	//   return base;
	// }
}

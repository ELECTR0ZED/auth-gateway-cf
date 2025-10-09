import type { ProviderConfig } from "../core/types";
import { AuthProvider } from "./baseProvider";

export class DiscordProvider extends AuthProvider {
  id = "discord" as const;

  protected getAuthorizeEndpoint(_: ProviderConfig): string {
    return "https://discord.com/api/oauth2/authorize";
  }

  protected getTokenEndpoint(_: ProviderConfig): string {
    return "https://discord.com/api/oauth2/token";
  }

  protected getDefaultScope(cfg: ProviderConfig): string {
    // 'identify' gives user id/username; add 'email' if you need email
    return cfg.scope ?? "identify email";
  }

  protected async fetchUserInfo(_: ProviderConfig, accessToken: string): Promise<{ claims: any }> {
    const r = await fetch("https://discord.com/api/users/@me", {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    if (!r.ok) throw new Error(`userinfo failed: ${r.status}`);
    const u = await r.json() as any;
    // Discord doesn't do OIDC id_token here; construct claims
    const claims = {
      sub: u.id,            // string
      email: u.email ?? undefined,
      username: u.username, // plus discriminator if needed
    };
    return { claims };
  }
}

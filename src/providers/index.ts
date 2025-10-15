import type { AuthProvider } from "./baseProvider";
import { AzureB2CProvider } from "./azureB2c";
import { GoogleProvider } from "./google";
import { GitHubProvider } from "./github";
import { DiscordProvider } from "./discord";
import { MicrosoftEntraProvider } from "./microsoft";

export const ProviderRegistry: Record<string, AuthProvider> = {
	azure_b2c: new AzureB2CProvider(),
	google: new GoogleProvider(),
	github: new GitHubProvider(),
	discord: new DiscordProvider(),
	entra: new MicrosoftEntraProvider(),
};

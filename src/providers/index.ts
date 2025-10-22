import type { AuthProvider } from './baseProvider';
import { GoogleProvider } from './google';

export const ProviderRegistry: Record<string, AuthProvider> = {
	google: new GoogleProvider(),
};

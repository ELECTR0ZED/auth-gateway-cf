import type { PasswordPolicy } from '../types';

const DEFAULT_POLICY: PasswordPolicy = {
	minLength: 12,
	requireUppercase: true,
	requireLowercase: true,
	requireNumber: true,
	requireSymbol: true,
};

export function getPasswordPolicy(cfg?: PasswordPolicy): PasswordPolicy {
	return { ...DEFAULT_POLICY, ...cfg };
}

export function validatePassword(password: string, policy: PasswordPolicy): { ok: true } | { ok: false; reason: string } {
	if (password.length < policy.minLength) {
		return { ok: false, reason: 'too_short' };
	}

	if (policy.requireUppercase && !/[A-Z]/.test(password)) {
		return { ok: false, reason: 'missing_uppercase' };
	}

	if (policy.requireLowercase && !/[a-z]/.test(password)) {
		return { ok: false, reason: 'missing_lowercase' };
	}

	if (policy.requireNumber && !/[0-9]/.test(password)) {
		return { ok: false, reason: 'missing_number' };
	}

	if (policy.requireSymbol && !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
		return { ok: false, reason: 'missing_symbol' };
	}

	return { ok: true };
}

export function hasAnyRole(userRoles: string[], required: string[]): boolean {
	if (!Array.isArray(userRoles) || userRoles.length === 0) return false;
	if (!Array.isArray(required) || required.length === 0) return false;

	const roles = new Set(userRoles);

	for (const role of required) {
		if (roles.has(role)) return true;
	}

	return false;
}

export function hasAllRoles(userRoles: string[], required: string[]): boolean {
	if (!Array.isArray(userRoles)) return false;
	if (!Array.isArray(required) || required.length === 0) return true;

	const roles = new Set(userRoles);

	for (const role of required) {
		if (!roles.has(role)) return false;
	}

	return true;
}

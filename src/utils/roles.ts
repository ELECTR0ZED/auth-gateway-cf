export function hasAnyRole(userRoles: string[], required: string[]): boolean {
	if (!Array.isArray(userRoles) || userRoles.length === 0) return false;
	const set = new Set(userRoles);
	for (const r of required) {
		if (set.has(r)) return true;
	}
	return false;
}

export function hasAllRoles(userRoles: string[], required: string[]): boolean {
	if (!Array.isArray(userRoles)) return false;
	if (required.length === 0) return true; // no roles required

	const set = new Set(userRoles);
	for (const r of required) {
		if (!set.has(r)) return false;
	}
	return true;
}

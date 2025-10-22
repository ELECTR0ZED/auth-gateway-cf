import type { RouteRule } from '../types';

/**
 * Ordered, short-circuit route matcher.
 * - First matching rule wins (stop on first hit).
 * - String paths are globbed ("**" any depth, "*" segment); trailing slash optional.
 * - RegExp paths are used as-is.
 * - Methods are case-insensitive; empty = any method.
 */
export class RouteMatcher {
	private compiled: Array<{ rule: RouteRule; tests: Array<{ re: RegExp; methods?: string[] }> }>;

	constructor(rules: RouteRule[]) {
		this.compiled = rules.map((rule) => {
			const arr = Array.isArray(rule.match) ? rule.match : [rule.match];
			const tests = arr.map((m) => ({
				re: toRegex(m.path),
				methods: m.methods?.map(up),
			}));
			return { rule, tests };
		});
	}

	/** Returns the FIRST matching rule, or undefined. */
	match(url: URL, method: string): RouteRule | undefined {
		const path = normalizePath(url.pathname);
		const m = up(method);

		for (const entry of this.compiled) {
			for (const t of entry.tests) {
				const methodOk = !t.methods || t.methods.includes(m);
				if (!methodOk) continue;
				if (t.re.test(path)) {
					return entry.rule; // short-circuit on first hit
				}
			}
		}
		return undefined;
	}
}

/** Normalizes path: removes trailing slash except for "/" */
function normalizePath(p: string): string {
	return p.length > 1 && p.endsWith('/') ? p.slice(0, -1) : p;
}

function up(s: string) {
	return s.toUpperCase();
}

/**
 * Converts a string glob to a RegExp with optional trailing slash.
 * - "**" -> ".*" (any depth)
 * - "*"  -> "[^/]*" (single segment portion)
 * If input is already RegExp, return as-is (no trailing-slash tweak).
 */
function toRegex(path: string | RegExp): RegExp {
	if (path instanceof RegExp) return path;

	// normalize pattern's trailing slash too (except root)
	let pat = path;
	if (pat.length > 1 && pat.endsWith('/')) pat = pat.slice(0, -1);

	pat = pat
		.replace(/[.+^${}()|[\]\\]/g, '\\$&')
		.replace(/\*\\\*/g, '**') // if someone escaped earlier, undo
		.replace(/\*\*/g, '.*')
		.replace(/\*/g, '[^/]*');

	const optSlash = pat === '/' ? '' : '(?:/)?';
	return new RegExp(`^${pat}${optSlash}$`);
}

import type { RouteRule } from '../types';

/**
 * Ordered, short-circuit route matcher.
 * - First matching rule wins (stop on first hit).
 * - String paths are globbed ("**" any depth, "*" segment); trailing slash optional.
 * - RegExp paths are used as-is.
 * - Methods are case-insensitive; empty = any method.
 */
export class RouteMatcher {
	private compiled: Array<{
		rule: RouteRule;
		tests: Array<{
			pathRe: RegExp;
			hostRe?: RegExp;
			methods?: string[];
		}>;
	}>;

	constructor(rules: RouteRule[]) {
		this.compiled = rules.map((rule) => {
			const arr = Array.isArray(rule.match) ? rule.match : [rule.match];
			const tests = arr.map((m) => ({
				pathRe: toPathRegex(m.path),
				hostRe: m.host ? toHostRegex(m.host) : undefined,
				methods: m.methods?.map(up),
			}));
			return { rule, tests };
		});
	}

	/** Returns the FIRST matching rule, or undefined. */
	match(url: URL, method: string): RouteRule | undefined {
		const path = normalizePath(url.pathname);
		const host = normalizeHost(url.hostname);
		const m = up(method);

		for (const entry of this.compiled) {
			for (const t of entry.tests) {
				const methodOk = !t.methods || t.methods.includes(m);
				if (!methodOk) continue;

				const hostOk = !t.hostRe || t.hostRe.test(host);
				if (!hostOk) continue;

				if (t.pathRe.test(path)) {
					return entry.rule;
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

function normalizeHost(h: string): string {
	return h.toLowerCase().replace(/\.$/, '');
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
function toPathRegex(path: string | RegExp): RegExp {
	if (path instanceof RegExp) return path;

	// normalize pattern's trailing slash too (except root)
	let pat = path;
	if (pat.length > 1 && pat.endsWith('/')) pat = pat.slice(0, -1);

	pat = globToRegexSource(pat, '/');

	const optSlash = pat === '/' ? '' : '(?:/)?';
	return new RegExp(`^${pat}${optSlash}$`);
}

function toHostRegex(host: string | RegExp): RegExp {
	if (host instanceof RegExp) return host;

	const pat = globToRegexSource(normalizeHost(host), '.');
	return new RegExp(`^${pat}$`, 'i');
}

function globToRegexSource(input: string, segmentSeparator: '/' | '.'): string {
	const segmentPattern = segmentSeparator === '/' ? '[^/]*' : '[^.]*';

	return input
		.replace(/[.+^${}()|[\]\\]/g, '\\$&')
		.replace(/\*\\\*/g, '**')
		.replace(/\*\*/g, '.*')
		.replace(/\*/g, segmentPattern);
}

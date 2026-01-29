import { uniqueNamesGenerator, Config, adjectives, animals } from 'unique-names-generator';

const emailRegex =
	/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

export const normEmail = (e: string) => e.trim().toLowerCase();

export const validateEmail = (email: string): boolean => {
	return emailRegex.test(email);
};

export const usernameRegex = /^[A-Za-z0-9_-]+$/;

export const normUsername = (u: string) => u.trim();

export const validateUsername = (username: string): boolean => {
	return usernameRegex.test(username);
};

export const STATIC_ASSET_RE = /\.(?:css|js|mjs|png|jpg|jpeg|gif|webp|svg|ico|woff2?|ttf|otf)$/i;

export const generateUsername = (_: string): string => {
	const config: Config = {
		dictionaries: [adjectives, animals],
		separator: '-',
		length: 2,
		style: 'capital',
	};
	return uniqueNamesGenerator(config) + '-' + Math.random().toString(36).substring(2, 6);
};

import type { UserCore, UserStore } from '../types';

/**
 * KV-backed UserStore for Cloudflare Workers.
 * Keys:
 *  - u:email:<email> -> userId
 *  - u:id:<userId> -> { id, email }
 *  - id:iss:<issuer>|sub:<subject> -> userId
 *  - ids:byUser:<userId> -> JSON array of { provider, issuer, subject }
 *
 * NOTE: KV is not transactional; for full consistency use a Postgres impl later.
 */
export class KvUserStore implements UserStore {
	constructor(private kv: KVNamespace) {}

	private kEmail(emailLower: string) {
		return `u:email:${emailLower}`;
	}
	private kUser(userId: string) {
		return `u:id:${userId}`;
	}
	private kIdentity(issuer: string, subject: string) {
		return `id:iss:${issuer}|sub:${subject}`;
	}
	private kUserIdentities(userId: string) {
		return `ids:byUser:${userId}`;
	}

	async findUserIdByIdentity(issuer: string, subject: string): Promise<string | null> {
		return (await this.kv.get(this.kIdentity(issuer, subject))) || null;
	}

	async findUserIdByEmail(emailLower: string): Promise<string | null> {
		return (await this.kv.get(this.kEmail(emailLower))) || null;
	}

	async createUserWithIdentity(emailLower: string, identity: { provider: string; issuer: string; subject: string }): Promise<string> {
		const existingByEmail = await this.findUserIdByEmail(emailLower);
		if (existingByEmail) throw new Error('account_exists');

		const existingByIdentity = await this.findUserIdByIdentity(identity.issuer, identity.subject);
		if (existingByIdentity) return existingByIdentity;

		const userId = crypto.randomUUID();

		const user: UserCore = { id: userId, email: emailLower };
		await this.kv.put(this.kEmail(emailLower), userId);
		await this.kv.put(this.kUser(userId), JSON.stringify(user));
		await this.kv.put(this.kIdentity(identity.issuer, identity.subject), userId);

		const ids = [{ provider: identity.provider, issuer: identity.issuer, subject: identity.subject }];
		await this.kv.put(this.kUserIdentities(userId), JSON.stringify(ids));

		return userId;
	}

	async addIdentityToUser(userId: string, identity: { provider: string; issuer: string; subject: string }): Promise<void> {
		const claimed = await this.findUserIdByIdentity(identity.issuer, identity.subject);
		if (claimed && claimed !== userId) {
			throw new Error('identity_taken');
		}
		await this.kv.put(this.kIdentity(identity.issuer, identity.subject), userId);

		const listRaw = (await this.kv.get(this.kUserIdentities(userId))) || '[]';
		const list = JSON.parse(listRaw) as Array<{ provider: string; issuer: string; subject: string }>;
		const exists = list.some((i) => i.issuer === identity.issuer && i.subject === identity.subject);
		if (!exists) {
			list.push(identity);
			await this.kv.put(this.kUserIdentities(userId), JSON.stringify(list));
		}
	}
}

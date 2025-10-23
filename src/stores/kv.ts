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

	private kEmail(email: string) {
		return `u:email:${email}`;
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

	async findUserIdByEmail(email: string): Promise<string | null> {
		return (await this.kv.get(this.kEmail(email))) || null;
	}

	async createUserWithIdentity(email: string, identity: { provider: string; issuer: string; subject: string }): Promise<string> {
		const existingByEmail = await this.findUserIdByEmail(email);
		if (existingByEmail) throw new Error('account_exists');

		const existingByIdentity = await this.findUserIdByIdentity(identity.issuer, identity.subject);
		if (existingByIdentity) return existingByIdentity;

		const userId = crypto.randomUUID();

		const user: UserCore = { id: userId, email };
		await this.kv.put(this.kEmail(email), userId);
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
		const list = JSON.parse(listRaw) as Array<{
			provider: string;
			issuer: string;
			subject: string;
		}>;
		const exists = list.some((i) => i.issuer === identity.issuer && i.subject === identity.subject);
		if (!exists) {
			list.push(identity);
			await this.kv.put(this.kUserIdentities(userId), JSON.stringify(list));
		}
	}
}

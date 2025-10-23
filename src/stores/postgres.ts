import type { UserStore } from '../types';
import { Pool } from 'pg';
import { Kysely, PostgresDialect, type Generated } from 'kysely';

// --- DB shape for Kysely type-safety ---
interface DB {
	users: {
		id: string; // uuid (pk)
		email: string;
		created_at: Date;
		updated_at: Date;
	};
	user_identities: {
		id: Generated<number>; // bigserial
		user_id: string; // uuid -> users.id
		provider: string;
		issuer: string;
		subject: string;
		created_at: Date;
	};
}

export class PostgresUserStore implements UserStore {
	private pool: Pool;
	private db: Kysely<DB>;

	constructor(hyperdrive: Hyperdrive) {
		this.pool = new Pool({
			connectionString: hyperdrive.connectionString,
			max: 5, // keep small in Workers
		});
		this.db = new Kysely<DB>({
			dialect: new PostgresDialect({ pool: this.pool }),
		});
	}

	async findUserIdByIdentity(issuer: string, subject: string): Promise<string | null> {
		const row = await this.db
			.selectFrom('user_identities as ui')
			.innerJoin('users as u', 'u.id', 'ui.user_id')
			.select('u.id')
			.where('ui.issuer', '=', issuer)
			.where('ui.subject', '=', subject)
			.selectAll('u')
			.select(['u.id'])
			.executeTakeFirst();

		return row?.id ?? null;
	}

	async findUserIdByEmail(email: string): Promise<string | null> {
		const row = await this.db.selectFrom('users').select('id').where('email', '=', email).executeTakeFirst();

		return row?.id ?? null;
	}

	async createUserWithIdentity(email: string, identity: { provider: string; issuer: string; subject: string }): Promise<string> {
		return this.db.transaction().execute(async (trx) => {
			// 1) If identity already exists, return its user (idempotent for re-login).
			const existing = await trx
				.selectFrom('user_identities as ui')
				.innerJoin('users as u', 'u.id', 'ui.user_id')
				.select(['u.id'])
				.where('ui.issuer', '=', identity.issuer)
				.where('ui.subject', '=', identity.subject)
				.executeTakeFirst();

			if (existing?.id) {
				return existing.id;
			}

			// 2) Ensure user exists or detect unique email conflict.
			// Prefer INSERT ... ON CONFLICT DO NOTHING RETURNING id
			const insertedUser = await trx
				.insertInto('users')
				.values({
					email,
				})
				.onConflict((oc) => oc.column('email').doNothing())
				.returning(['id'])
				.executeTakeFirst();

			const userId = insertedUser?.id;
			if (!userId) {
				// No row inserted → email already exists. Fetch to confirm and error out.
				const existingUser = await trx.selectFrom('users').select(['id']).where('email', '=', email).executeTakeFirst();

				if (existingUser?.id) {
					throw new Error('account_exists');
				}
				// If we got here, something else prevented insert; surface a generic error.
				throw new Error('signup_failed');
			}

			// 3) Bind identity. If (issuer, subject) already taken by another user, fail.
			const insertedIdentity = await trx
				.insertInto('user_identities')
				.values({
					user_id: userId,
					provider: identity.provider,
					issuer: identity.issuer,
					subject: identity.subject,
				})
				.onConflict((oc) => oc.columns(['issuer', 'subject']).doNothing())
				.returning(['user_id'])
				.executeTakeFirst();

			if (!insertedIdentity) {
				// Conflict on (issuer, subject). Check owner.
				const owner = await trx
					.selectFrom('user_identities')
					.select(['user_id'])
					.where('issuer', '=', identity.issuer)
					.where('subject', '=', identity.subject)
					.executeTakeFirst();

				if (owner?.user_id && owner.user_id !== userId) {
					// In "create" flow, an existing identity implies the account already exists.
					throw new Error('account_exists');
				}
				// Else identity already linked to this user (idempotent), fall through.
			}

			return userId;
		});
	}

	async addIdentityToUser(userId: string, identity: { provider: string; issuer: string; subject: string }): Promise<void> {
		const res = await this.db
			.insertInto('user_identities')
			.values({
				user_id: userId,
				provider: identity.provider,
				issuer: identity.issuer,
				subject: identity.subject,
			})
			.onConflict((oc) => oc.columns(['issuer', 'subject']).doNothing())
			.returning(['user_id'])
			.executeTakeFirst();

		if (!res) {
			// Conflict on (issuer, subject). Check who owns it.
			const owner = await this.db
				.selectFrom('user_identities')
				.select(['user_id'])
				.where('issuer', '=', identity.issuer)
				.where('subject', '=', identity.subject)
				.executeTakeFirst();

			if (owner?.user_id && owner.user_id !== userId) {
				throw new Error('identity_taken');
			}
			// Already linked to this user → no-op.
		}
	}

	// Optional: call on worker shutdown if you manage lifecycle explicitly
	async destroy(): Promise<void> {
		await this.db.destroy();
		await this.pool.end();
	}
}

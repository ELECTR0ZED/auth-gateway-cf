import type { UserStore } from '../types';
import { Pool } from 'pg';
import { Kysely, PostgresDialect, type Generated } from 'kysely';

// --- DB shape for Kysely type-safety ---
// Mark DB-populated columns as Generated<...> so inserts don't require them.
interface DB {
	users: {
		id: Generated<string>; // uuid DEFAULT uuid_generate_v4()
		email: string; // unique
		system_roles: Generated<string[]>; // text[]
		created_at: Generated<Date>; // DEFAULT now()
	};
	user_identities: {
		id: Generated<number>; // bigserial
		user_id: string; // uuid -> users.id
		provider: string;
		issuer: string;
		subject: string;
		created_at: Generated<Date>; // DEFAULT now()
	};
	user_passwords: {
		user_id: string; // uuid -> users.id
		password_hash: string; // stored hash
		created_at: Generated<Date>; // DEFAULT now()
		updated_at: Generated<Date>; // DEFAULT now()
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
			.select(['u.id'])
			.where('ui.issuer', '=', issuer)
			.where('ui.subject', '=', subject)
			.executeTakeFirst();

		return row?.id ?? null;
		// (Optional) .execute() returns array; .executeTakeFirst() returns a single row or undefined.
	}

	async findUserIdByEmail(email: string): Promise<string | null> {
		const row = await this.db.selectFrom('users').select('id').where('email', '=', email).executeTakeFirst();

		return row?.id ?? null;
	}

	async createUserWithIdentity(email: string, identity: { provider: string; issuer: string; subject: string }): Promise<string> {
		return this.db.transaction().execute(async (trx) => {
			// 1) Idempotency: if identity already exists, return its user.
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

			// 2) Create-or-detect user by email
			const insertedUser = await trx
				.insertInto('users')
				.values({ email })
				.onConflict((oc) => oc.column('email').doNothing())
				.returning(['id'])
				.executeTakeFirst();

			const userId = insertedUser?.id;
			if (!userId) {
				// No row inserted → email already exists. Confirm and throw account_exists.
				const existingUser = await trx.selectFrom('users').select(['id']).where('email', '=', email).executeTakeFirst();

				if (existingUser?.id) {
					throw new Error('account_exists');
				}
				throw new Error('signup_failed');
			}

			// 3) Bind identity. If (issuer, subject) owned by another user, fail.
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
				// Conflict → check owner
				const owner = await trx
					.selectFrom('user_identities')
					.select(['user_id'])
					.where('issuer', '=', identity.issuer)
					.where('subject', '=', identity.subject)
					.executeTakeFirst();

				if (owner?.user_id && owner.user_id !== userId) {
					throw new Error('account_exists');
				}
				// else already linked to this user → idempotent
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
			// Conflict → figure out owner
			const owner = await this.db
				.selectFrom('user_identities')
				.select(['user_id'])
				.where('issuer', '=', identity.issuer)
				.where('subject', '=', identity.subject)
				.executeTakeFirst();

			if (owner?.user_id && owner.user_id !== userId) {
				throw new Error('identity_taken');
			}
			// already linked to same user → no-op
		}
	}

	async getUserRoles(userId: string): Promise<string[]> {
		const row = await this.db.selectFrom('users').select('system_roles').where('id', '=', userId).executeTakeFirst();

		return row?.system_roles ?? [];
	}

	async createUserWithPassword(email: string, passwordHash: string): Promise<string> {
		return this.db.transaction().execute(async (trx) => {
			// Create user (email unique). If it already exists -> account_exists
			const insertedUser = await trx
				.insertInto('users')
				.values({ email })
				.onConflict((oc) => oc.column('email').doNothing())
				.returning(['id'])
				.executeTakeFirst();

			const userId = insertedUser?.id;
			if (!userId) {
				throw new Error('account_exists');
			}

			// Attach password hash (should succeed; user_id PK)
			await trx
				.insertInto('user_passwords')
				.values({
					user_id: userId,
					password_hash: passwordHash,
				})
				.execute();

			return userId;
		});
	}

	async getUserIdByEmailForPassword(email: string): Promise<{ userId: string; passwordHash: string } | null> {
		const row = await this.db
			.selectFrom('users as u')
			.innerJoin('user_passwords as up', 'up.user_id', 'u.id')
			.select(['u.id as userId', 'up.password_hash as passwordHash'])
			.where('u.email', '=', email)
			.executeTakeFirst();

		return row ?? null;
	}

	async getPasswordHashByUserId(userId: string): Promise<string | null> {
		const row = await this.db.selectFrom('user_passwords').select(['password_hash']).where('user_id', '=', userId).executeTakeFirst();

		return row?.password_hash ?? null;
	}

	async setPasswordHash(userId: string, passwordHash: string): Promise<void> {
		await this.db
			.insertInto('user_passwords')
			.values({
				user_id: userId,
				password_hash: passwordHash,
			})
			.onConflict((oc) =>
				oc.column('user_id').doUpdateSet({
					password_hash: passwordHash,
					updated_at: new Date(),
				}),
			)
			.execute();
	}

	async destroy(): Promise<void> {
		await this.db.destroy();
		await this.pool.end();
	}
}

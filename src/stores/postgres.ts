import type { UserStore } from '../types';
import { Pool } from 'pg';
import { Kysely, PostgresDialect, type Transaction, type Generated } from 'kysely';

// --- DB shape for Kysely type-safety ---
// Mark DB-populated columns as Generated<...> so inserts don't require them.
export interface DB {
	users: {
		id: Generated<string>; // uuid DEFAULT uuid_generate_v4()
		username: string | null; // unique, nullable
		email: string; // unique
		system_roles: Generated<string[]>; // text[]
		created_at: Generated<Date>; // DEFAULT now()
		last_login_at: Date | null;
	};
	user_states: {
		user_id: string;

		is_disabled: boolean;
		disabled_at: Date | null;
		disabled_by: string | null;

		is_approved: boolean;
		approved_at: Date | null;
		approved_by: string | null;

		is_email_verified: boolean;
		email_verified_at: Date | null;
		email_verification_token_hash: string | null;

		created_at: Date;
		updated_at: Date;
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

	async createUserWithIdentity(
		email: string,
		identity: { provider: string; issuer: string; subject: string },
		generateUsernameFunc?: (email: string) => string,
	): Promise<string> {
		return this.db.transaction().execute(async (trx) => {
			if (await this.checkEmailExists(email)) {
				throw new Error('email_in_use');
			}
			let username: string | null = null;
			if (generateUsernameFunc) {
				let attempts = 0;
				while (attempts < 5) {
					const generated = generateUsernameFunc(email);
					if (!(await this.checkUsernameExists(generated))) {
						username = generated;
						break;
					}
					attempts++;
				}
				if (!username) {
					throw new Error('username_generation_failed');
				}
			}
			// 1) Create-or-detect user by email
			const insertedUser = await this.createUser(trx, email, username);

			const userId = insertedUser?.id;
			if (!userId) {
				throw new Error('account_exists');
			}

			// 2) Bind identity. If (issuer, subject) owned by another user, fail.
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

			// 3) Create user_states row
			await this.createUserStates(trx, userId);

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

	async getUserStates(userId: string): Promise<DB['user_states'] | null> {
		const row = await this.db.selectFrom('user_states').selectAll().where('user_id', '=', userId).executeTakeFirst();

		return row || null;
	}

	async createUser(trx: Transaction<DB>, email: string, username: string | null = null): Promise<{ id: string } | undefined> {
		try {
			return await trx
				.insertInto('users')
				.values({ email, username })
				.onConflict((oc) => oc.column('email').doNothing())
				.returning(['id'])
				.executeTakeFirst();
		} catch (err: unknown) {
			// Normalize unique-constraint violations so callers can distinguish causes.
			// Postgres uses SQLSTATE '23505' for unique_violation errors.
			if (err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === '23505') {
				const constraint: unknown = 'constraint' in err ? (err as { constraint: string }).constraint : undefined;
				if (typeof constraint === 'string') {
					if (constraint.includes('email')) {
						throw new Error('email_in_use');
					}
					if (constraint.includes('username')) {
						throw new Error('username_in_use');
					}
				}
			}
			throw err;
		}
	}

	async createUserStates(trx: Transaction<DB>, userId: string): Promise<void> {
		await trx
			.insertInto('user_states')
			.values({
				user_id: userId,

				is_disabled: false,
				disabled_at: null,
				disabled_by: null,

				is_approved: false,
				approved_at: null,
				approved_by: null,

				is_email_verified: false,
				email_verified_at: null,
				email_verification_token_hash: null,

				created_at: new Date(),
				updated_at: new Date(),
			})
			.execute();
	}

	async createUserWithPassword(email: string, passwordHash: string, username: string | null = null): Promise<string> {
		return this.db.transaction().execute(async (trx) => {
			if (await this.checkEmailExists(email)) {
				throw new Error('email_in_use');
			}
			if (username && (await this.checkUsernameExists(username))) {
				throw new Error('username_in_use');
			}

			// Create user (email unique). If it already exists -> account_exists
			const insertedUser = await this.createUser(trx, email, username);
			const userId = insertedUser?.id;
			if (!userId) {
				throw new Error('account_exists');
			}

			// Set password
			await trx
				.insertInto('user_passwords')
				.values({
					user_id: userId,
					password_hash: passwordHash,
				})
				.execute();

			// Create user_states row
			await this.createUserStates(trx, userId);

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

	async checkUsernameExists(username: string): Promise<boolean> {
		const row = await this.db.selectFrom('users').select('id').where('username', '=', username).executeTakeFirst();
		return !!row;
	}

	async checkEmailExists(email: string): Promise<boolean> {
		const row = await this.db.selectFrom('users').select('id').where('email', '=', email).executeTakeFirst();
		return !!row;
	}

	async destroy(): Promise<void> {
		await this.db.destroy();
		await this.pool.end();
	}
}

import type { UserStoreCfg, UserStore } from '../types';
import { PostgresUserStore } from './postgres';

export function makeUserStore(cfg: UserStoreCfg): UserStore {
	switch (cfg.kind) {
		case 'postgres':
			return new PostgresUserStore(cfg.hyperdrive);
		default:
			throw new Error('UserStore kind not supported in this build');
	}
}

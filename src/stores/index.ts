import type { UserStoreCfg, UserStore } from '../types';
import { KvUserStore } from './kv';

export function makeUserStore(cfg: UserStoreCfg): UserStore {
	switch (cfg.kind) {
		case 'kv':
			return new KvUserStore(cfg.kv);
		default:
			throw new Error('UserStore kind not supported in this build');
	}
}

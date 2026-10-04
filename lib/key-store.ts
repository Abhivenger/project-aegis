// ============================================================================
// PROJECT AEGIS: LOCAL FALLBACK API KEY STORE
// Persists generated API keys when Supabase is unavailable, so the /api/keys
// routes remain functional and the dashboard's key table populates immediately.
//
// Keys are grouped by userId so one local operator's keys never leak into
// another tenant's table. The file store is intentionally simple and never
// used when a real Supabase client is present.
// ============================================================================

import { randomBytes, createHash } from 'crypto';
import { promises as fs } from 'fs';
import { dirname } from 'path';

export interface StoredApiKey {
  id: string;
  user_id: string;
  key_name: string;
  key_prefix: string;
  hashed_key: string;
  plaintext_secret: string;
  plaintextSecret?: string;
  created_at: string;
  last_used_at: string | null;
}

export interface StoredApiKeysList {
  keys: StoredApiKey[];
}

export function mapStoredKey(row: StoredApiKey): {
  id: string;
  key_name: string;
  key_prefix: string;
  created_at: string;
} {
  return {
    id: row.id,
    key_name: row.key_name,
    key_prefix: row.key_prefix,
    created_at: row.created_at,
  };
}

export function mapInsertedKey(row: StoredApiKey): {
  id: string;
  name: string;
  prefix: string;
  plaintextSecret: string;
  createdAt: string;
} {
  return {
    id: row.id,
    name: row.key_name,
    prefix: row.key_prefix,
    plaintextSecret: row.plaintext_secret,
    createdAt: row.created_at,
  };
}

function storageRoot(): string {
  if (typeof process !== 'undefined' && typeof process.cwd === 'function') {
    return process.cwd();
  }
  return '.';
}

async function writeDiskStore(path: string, data: StoredApiKeysList): Promise<void> {
  const dir = dirname(path);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(path, JSON.stringify(data, null, 2), 'utf-8');
}

async function readDiskStore(path: string): Promise<StoredApiKeysList> {
  try {
    const raw = await fs.readFile(path, 'utf-8');
    if (!raw.trim()) {
      return { keys: [] };
    }
    const data = JSON.parse(raw) as StoredApiKeysList;
    return Array.isArray(data.keys) ? data : { keys: [] };
  } catch {
    return { keys: [] };
  }
}

/** In-memory hashmap keyed by userId. */
const MEMORY_STORE = new Map<string, StoredApiKey[]>();

function isSupabaseAvailable(): boolean {
  try {
    const { getServiceSupabase } = require('@/lib/supabase/server');
    return getServiceSupabase() !== null;
  } catch {
    return false;
  }
}

/**
 * Returns the in-memory store for a given userId. This runs when Supabase is
 * unavailable; the filesystem mirror is still written eagerly so restarts
 * survive.
 */
function getStore(userId: string): StoredApiKey[] {
  if (!MEMORY_STORE.has(userId)) {
    MEMORY_STORE.set(userId, []);
  }
  return MEMORY_STORE.get(userId)!;
}

export interface GeneratedApiKey {
  id: string;
  user_id: string;
  key_name: string;
  key_prefix: string;
  hashed_key: string;
  plaintext_secret: string;
  created_at: string;
  last_used_at: string | null;
}

export async function generateStoredApiKey(
  userId: string,
  name: string
): Promise<GeneratedApiKey> {
  const rawToken = `aegis_live_${randomBytes(24).toString('hex')}`;
  const keyPrefix = rawToken.slice(0, 19); // aegis_live_ + first 8 characters
  const hashedKey = createHash('sha256').update(rawToken).digest('hex');
  const now = new Date().toISOString();

  const row: StoredApiKey = {
    id: randomBytes(16).toString('hex'),
    user_id: userId,
    key_name: name,
    key_prefix: keyPrefix,
    hashed_key: hashedKey,
    plaintext_secret: rawToken,
    plaintextSecret: rawToken,
    created_at: now,
    last_used_at: null,
  };

  getStore(userId).push(row);

  // Best-effort filesystem mirror so restarts survive when Supabase is absent.
  const dataPath = `.data/api-keys.json`;
  try {
    const dir = dirname(dataPath);
    await fs.mkdir(dir, { recursive: true });
    const path = dataPath.startsWith('/')
      ? dataPath
      : `${storageRoot()}/${dataPath}`.replace(/\/+/g, '/');
    const existing = await readDiskStore(path);
    existing.keys.push(row);
    await writeDiskStore(path, existing);
  } catch {
    // Non-fatal: keys still exist in memory and in the caller response.
  }

  return row;
}

export type LocalKeyListItem = ReturnType<typeof mapStoredKey>;

export function listStoredKeys(userId: string): LocalKeyListItem[] {
  if (isSupabaseAvailable()) {
    return [];
  }
  return getStore(userId).map(mapStoredKey);
}

/**
 * Remove a key (idempotent) from the local fallback store.
 */
export function removeStoredKey(userId: string, keyId: string): void {
  const store = getStore(userId);
  const idx = store.findIndex((row) => row.id === keyId);
  if (idx >= 0) {
    store.splice(idx, 1);
  }
}

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

/**
 * The vault node's keys: one active key that seals new values, and the keys before a rotation, kept until nothing is
 * sealed with them. They exist only in the node's memory; on disk (or with the host) they are always wrapped.
 *
 * A sealed value: n1.<key id>.<shape>.<iv | tag | body>, all base64url.
 * - The shape is what the bot may know without opening the value (which fields a card has, what kind of ID a login
 *   uses). It is chosen by whoever seals, readable by anyone, and bound to the value: changed, the value does not open.
 * - The context (shop_vault/<user>/<entry>) is bound the same way: a value moved to another user or entry does not
 *   open there.
 */
export interface NodeKey {
  id: string;
  key: Buffer;
}

export type Shape = Record<string, unknown>;

export const keyId = (key: Buffer) => createHash('sha256').update('byme-vault-node-kid:').update(key).digest('hex').slice(0, 12);

export function nodeKey(key: Buffer): NodeKey {
  if (key.length !== 32) throw new Error('A vault node key is 32 bytes.');
  return { id: keyId(key), key };
}

const SEALED = /^n1\.([0-9a-f]{12})\.([A-Za-z0-9_-]*)\.([A-Za-z0-9_-]+)$/;

/** The shape of a sealed value, without opening it ({} when it is not one of the node's). */
export function shapeOf(sealed: string): Shape {
  const m = SEALED.exec(sealed);
  if (!m || !m[2]) return {};
  try {
    const v = JSON.parse(Buffer.from(m[2], 'base64url').toString('utf8'));
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Shape) : {};
  } catch {
    return {};
  }
}

export const isNodeSealed = (sealed: string) => SEALED.test(sealed);
export const sealedKeyId = (sealed: string) => SEALED.exec(sealed)?.[1] ?? null;

const aad = (context: string, shape: string) => Buffer.from(`byme-vault-node\0${context}\0${shape}`, 'utf8');

export class Keyring {
  private activeKey: NodeKey;
  private readonly keys = new Map<string, NodeKey>();

  constructor(active: NodeKey, retired: NodeKey[] = []) {
    this.activeKey = active;
    for (const k of [active, ...retired]) this.keys.set(k.id, k);
  }

  static fresh(): Keyring {
    return new Keyring(nodeKey(randomBytes(32)));
  }

  get activeId(): string {
    return this.activeKey.id;
  }

  retiredIds(): string[] {
    return [...this.keys.keys()].filter((id) => id !== this.activeKey.id);
  }

  seal(context: string, value: unknown, shape: Shape = {}): string {
    const s = Object.keys(shape).length ? Buffer.from(JSON.stringify(shape), 'utf8').toString('base64url') : '';
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.activeKey.key, iv);
    c.setAAD(aad(context, s));
    const body = Buffer.concat([c.update(JSON.stringify(value), 'utf8'), c.final()]);
    return `n1.${this.activeKey.id}.${s}.${Buffer.concat([iv, c.getAuthTag(), body]).toString('base64url')}`;
  }

  /** The value, or null when it does not open here (another context, a changed shape, a key that is gone). */
  open(context: string, sealed: string): unknown {
    const m = SEALED.exec(sealed);
    const k = m && this.keys.get(m[1]);
    if (!m || !k) return null;
    try {
      const raw = Buffer.from(m[3], 'base64url');
      const d = createDecipheriv('aes-256-gcm', k.key, raw.subarray(0, 12));
      d.setAAD(aad(context, m[2]));
      d.setAuthTag(raw.subarray(12, 28));
      return JSON.parse(Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8'));
    } catch {
      return null;
    }
  }

  /** The same value under the active key, never leaving the node; null when it does not open. */
  reseal(context: string, sealed: string): string | null {
    const value = this.open(context, sealed);
    return value === null ? null : this.seal(context, value, shapeOf(sealed));
  }

  rotate(): void {
    const next = nodeKey(randomBytes(32));
    this.keys.set(next.id, next);
    this.activeKey = next;
  }

  /** Retired keys none of `used` names: gone for good. */
  prune(used: Set<string>): string[] {
    const gone = this.retiredIds().filter((id) => !used.has(id));
    for (const id of gone) this.keys.delete(id);
    return gone;
  }

  toJSON(): { active: string; keys: string[] } {
    return { active: this.activeKey.id, keys: [...this.keys.values()].map((k) => k.key.toString('hex')) };
  }

  static fromJSON(j: { active: string; keys: string[] }): Keyring {
    const all = j.keys.map((h) => nodeKey(Buffer.from(h, 'hex')));
    const active = all.find((k) => k.id === j.active);
    if (!active) throw new Error('The keyring names an active key it does not hold.');
    return new Keyring(active, all.filter((k) => k !== active));
  }
}

import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHash, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto';

/**
 * The node's own record of every value it opened and every key change: written before the act (a value is released
 * only once its entry is stored), signed with a key that lives only in this node and is named in its attestation, and
 * chained (each entry carries the hash of the one before), so the operator can neither forge an entry nor drop one
 * without a gap in the chain. No entry holds a value.
 */
export interface LogEntry {
  node: string;
  seq: number;
  at: number;
  /** The hash of the entry before ('' for the first of this node). */
  prev: string;
  action: 'boot' | 'release' | 'seal' | 'reseal' | 'rotate' | 'prune';
  user?: number;
  entry?: string;
  order?: number;
  site?: string;
  why?: string;
  /** The key a rotation made, or the keys a prune dropped. */
  keys?: string[];
}

export interface SignedEntry {
  line: string;
  hash: string;
  sig: string;
}

/** Where entries go; the act waits until every sink took the entry. */
export interface LogSink {
  write(e: LogEntry, signed: SignedEntry): Promise<void>;
}

export class FileSink implements LogSink {
  private readonly file: string;
  constructor(file: string) {
    this.file = file;
    mkdirSync(dirname(file), { recursive: true });
  }
  async write(_e: LogEntry, s: SignedEntry): Promise<void> {
    appendFileSync(this.file, `${JSON.stringify(s)}\n`, { mode: 0o600 });
  }
}

export class NodeLog {
  readonly publicKey: KeyObject;
  readonly nodeId: string;
  private readonly privateKey: KeyObject;
  private readonly sinks: LogSink[];
  private readonly recent: SignedEntry[] = [];
  private seq = 0;
  private head = '';
  /** Entries are written one at a time, so the chain has no forks. */
  private queue: Promise<unknown> = Promise.resolve();
  private readonly now: () => number;

  constructor(sinks: LogSink[], now: () => number = Date.now) {
    const pair = generateKeyPairSync('ed25519');
    this.publicKey = pair.publicKey;
    this.privateKey = pair.privateKey;
    this.nodeId = createHash('sha256').update(this.publicKeyDer()).digest('hex').slice(0, 16);
    this.sinks = sinks;
    this.now = now;
  }

  /** Another place entries go from now on (an enclave's bucket, once its host said which). */
  addSink(sink: LogSink): void {
    this.sinks.push(sink);
  }

  publicKeyDer(): Buffer {
    return this.publicKey.export({ type: 'spki', format: 'der' });
  }

  /** Appends an entry; resolves once every sink has it (reject = the act must not happen). */
  append(e: Omit<LogEntry, 'node' | 'seq' | 'at' | 'prev'>): Promise<SignedEntry> {
    const run = this.queue.then(async () => {
      const entry: LogEntry = { node: this.nodeId, seq: this.seq + 1, at: this.now(), prev: this.head, ...e };
      const line = JSON.stringify(entry);
      const signed: SignedEntry = { line, hash: createHash('sha256').update(line).digest('hex'), sig: sign(null, Buffer.from(line), this.privateKey).toString('base64') };
      for (const s of this.sinks) await s.write(entry, signed);
      this.seq = entry.seq;
      this.head = signed.hash;
      this.recent.push(signed);
      if (this.recent.length > 2000) this.recent.shift();
      return signed;
    });
    this.queue = run.catch(() => {});
    return run;
  }

  get headHash(): string {
    return this.head;
  }

  get length(): number {
    return this.seq;
  }

  /** The latest entries, a user's only when one is named. */
  entries(user?: number, limit = 100): SignedEntry[] {
    const all = user === undefined ? this.recent : this.recent.filter((s) => (JSON.parse(s.line) as LogEntry).user === user);
    return all.slice(-limit);
  }
}

/** Checks a run of entries from one node: each signed by its key, each pointing at the one before. */
export function checkChain(entries: SignedEntry[], publicKeyDer: Buffer): { ok: true } | { ok: false; at: number; why: string } {
  let prev: string | null = null;
  for (let i = 0; i < entries.length; i++) {
    const s = entries[i];
    const e = JSON.parse(s.line) as LogEntry;
    if (createHash('sha256').update(s.line).digest('hex') !== s.hash) return { ok: false, at: i, why: 'the hash does not match the entry' };
    if (!verify(null, Buffer.from(s.line), { key: publicKeyDer, format: 'der', type: 'spki' }, Buffer.from(s.sig, 'base64'))) return { ok: false, at: i, why: 'not signed by this node' };
    if (prev !== null && e.prev !== prev) return { ok: false, at: i, why: 'an entry before it is missing or changed' };
    prev = s.hash;
  }
  return { ok: true };
}

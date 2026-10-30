import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { join } from 'node:path';
import type { Attest, AwsCredentials, Kms } from './aws.ts';
import { Keyring, sealedKeyId, type Shape } from './keyring.ts';
import type { LogSink, NodeLog } from './log.ts';

/**
 * The vault node: the only program that holds the key to the user's most sensitive details (site passwords, the
 * card, payment PINs, 본인인증 details). The bot hands it a value to seal and stores what comes back; when a run needs
 * the value to type it, the bot asks the node to release it for that order, and the node writes that in its log
 * first. Run in an AWS Nitro Enclave, the key is in memory no operator can read, and anyone can check that the
 * program running is this one (see attestation.ts and enclave/README.md).
 */

/** Where the keyring lives between restarts: always encrypted, never where the bot's data is. */
export interface KeySource {
  readonly mode: 'file' | 'kms' | 'nitro';
  /** The keyring; `wrapped` is what the host kept from the last save (KMS without a folder of its own). */
  load(wrapped?: string): Promise<Keyring | null>;
  /** Keeps the keyring; returns what the host must keep, if anything. */
  save(ring: Keyring): Promise<string | null>;
}

/** The keyring in a file of the node's own volume (a container next to the bot, without KMS). */
export class FileKeys implements KeySource {
  readonly mode = 'file' as const;
  private readonly file: string;
  constructor(dir: string) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.file = join(dir, 'node.key');
  }
  async load(): Promise<Keyring> {
    if (existsSync(this.file)) return Keyring.fromJSON(JSON.parse(readFileSync(this.file, 'utf8')));
    const ring = Keyring.fresh();
    await this.save(ring);
    return ring;
  }
  async save(ring: Keyring): Promise<null> {
    writeAtomic(this.file, JSON.stringify(ring.toJSON()));
    return null;
  }
}

/**
 * The keyring sealed with a data key that AWS KMS wraps. In an enclave the data key comes back encrypted to the
 * enclave (see Kms), and KMS hands it only to an enclave whose measurements the key policy names. The wrapped
 * keyring is kept in `dir` if the node has one, else by the host (it is useless without KMS and the enclave).
 */
export class KmsKeys implements KeySource {
  readonly mode: 'kms' | 'nitro';
  private readonly kms: Kms;
  private readonly file: string | null;
  private dataKey: { plaintext: Buffer; blob: string } | null = null;

  constructor(kms: Kms, dir: string | null, attested: boolean) {
    this.kms = kms;
    this.mode = attested ? 'nitro' : 'kms';
    if (dir) mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.file = dir ? join(dir, 'node.wrapped') : null;
  }

  async load(wrapped?: string): Promise<Keyring | null> {
    const saved = this.file && existsSync(this.file) ? readFileSync(this.file, 'utf8').trim() : wrapped;
    if (saved) {
      const w = JSON.parse(saved) as { kms: string; ring: string };
      this.dataKey = { plaintext: await this.kms.decrypt(w.kms), blob: w.kms };
      const raw = Buffer.from(w.ring, 'base64');
      const d = createDecipheriv('aes-256-gcm', this.dataKey.plaintext, raw.subarray(0, 12));
      d.setAAD(Buffer.from('byme-vault-node-keyring'));
      d.setAuthTag(raw.subarray(12, 28));
      return Keyring.fromJSON(JSON.parse(Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8')));
    }
    // The host says it kept nothing: the first start. Without a folder, the host must keep what save returns.
    this.dataKey = await this.kms.generateDataKey();
    return Keyring.fresh();
  }

  async save(ring: Keyring): Promise<string | null> {
    if (!this.dataKey) throw new Error('The keyring was never loaded.');
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.dataKey.plaintext, iv);
    c.setAAD(Buffer.from('byme-vault-node-keyring'));
    const body = Buffer.concat([c.update(JSON.stringify(ring.toJSON()), 'utf8'), c.final()]);
    const wrapped = JSON.stringify({ kms: this.dataKey.blob, ring: Buffer.concat([iv, c.getAuthTag(), body]).toString('base64') });
    if (this.file) writeAtomic(this.file, wrapped);
    return wrapped;
  }
}

function writeAtomic(file: string, text: string): void {
  writeFileSync(`${file}.tmp`, `${text}\n`, { mode: 0o600 });
  renameSync(`${file}.tmp`, file);
}

/** Only values kept for a user are sealed here, so every log entry names whose value it was. */
const CONTEXT = /^shop_vault\/(\d+)\/([\w:.@-]{1,120})$/;
export function parseContext(context: string): { user: number; entry: string } {
  const m = CONTEXT.exec(context);
  if (!m) throw new NodeError(400, 'context must be shop_vault/<user>/<entry>');
  return { user: Number(m[1]), entry: m[2] };
}

export class NodeError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * What an enclave learns from its host once, at its first start: which KMS key wraps its keyring and where its log
 * goes. Not baked into the image (that would make every deployment's measurements different), so it is shown in the
 * attestation instead: a verifier sees which bucket the log of the node they checked goes to.
 */
export interface NodeSettings {
  kmsKeyId: string;
  region: string;
  logBucket?: string;
}

export interface Purpose {
  order?: number;
  site?: string;
  why: string;
}

export class VaultNode {
  readonly version: string;
  private keys: KeySource | null;
  private readonly log: NodeLog;
  private settings: NodeSettings | null = null;
  private readonly setup: ((s: NodeSettings) => { keys: KeySource; sinks: LogSink[] }) | null;
  private readonly attest: Attest;
  private ring: Keyring | null = null;
  private loading: Promise<string | null> | null = null;
  credentials: AwsCredentials | null = null;

  /** `keys`, or `setup` for a node told its settings by its host (POST /configure, once). */
  constructor(o: { keys?: KeySource; setup?: (s: NodeSettings) => { keys: KeySource; sinks: LogSink[] }; log: NodeLog; attest: Attest; version: string; credentials?: AwsCredentials | null }) {
    this.keys = o.keys ?? null;
    this.setup = o.setup ?? null;
    this.log = o.log;
    this.attest = o.attest;
    this.version = o.version;
    this.credentials = o.credentials ?? null;
  }

  get ready(): boolean {
    return !!this.ring;
  }

  /** The host's settings, once: a second call with others is refused (the log must not move to another bucket). */
  configure(s: NodeSettings): void {
    if (!this.setup) throw new NodeError(409, 'this node is configured by its environment');
    const clean: NodeSettings = { kmsKeyId: String(s.kmsKeyId ?? ''), region: String(s.region ?? ''), ...(s.logBucket ? { logBucket: String(s.logBucket) } : {}) };
    if (!clean.kmsKeyId || !/^[a-z]{2}-[a-z]+-\d$/.test(clean.region)) throw new NodeError(400, 'kmsKeyId and region are needed');
    if (this.settings) {
      if (JSON.stringify(this.settings) !== JSON.stringify(clean)) throw new NodeError(409, 'already configured with other settings');
      return;
    }
    const made = this.setup(clean);
    this.keys = made.keys;
    for (const sink of made.sinks) this.log.addSink(sink);
    this.settings = clean;
  }

  /** Opens the keyring (once). Returns what the host must keep, when it keeps the wrapped keyring. */
  unlock(wrapped?: string): Promise<string | null> {
    if (this.ring) return Promise.resolve(null);
    const keys = this.keys;
    if (!keys) return Promise.reject(new NodeError(503, 'not configured'));
    this.loading ??= (async () => {
      const ring = await keys.load(wrapped);
      if (!ring) throw new NodeError(503, 'locked');
      const out = wrapped ? null : await keys.save(ring);
      await this.log.append({ action: 'boot', keys: [ring.activeId], why: `${keys.mode} ${this.version}` });
      this.ring = ring;
      return out;
    })().finally(() => (this.loading = null));
    return this.loading;
  }

  private keyring(): Keyring {
    if (!this.ring) throw new NodeError(503, 'locked');
    return this.ring;
  }

  async seal(context: string, value: unknown, shape: Shape = {}): Promise<string> {
    const { user, entry } = parseContext(context);
    const ring = this.keyring();
    await this.log.append({ action: 'seal', user, entry });
    return ring.seal(context, value, shape);
  }

  /** The value, for one use the log names; null when it does not open (another user's, or its key is gone). */
  async release(context: string, sealed: string, purpose: Purpose): Promise<unknown> {
    const { user, entry } = parseContext(context);
    if (!purpose?.why) throw new NodeError(400, 'a release says what it is for');
    const ring = this.keyring();
    await this.log.append({ action: 'release', user, entry, why: String(purpose.why).slice(0, 80), ...(purpose.order ? { order: Number(purpose.order) } : {}), ...(purpose.site ? { site: String(purpose.site).slice(0, 120) } : {}) });
    return ring.open(context, sealed);
  }

  /** Sealed again under the active key: the value never leaves the node. */
  reseal(context: string, sealed: string): string | null {
    parseContext(context);
    return this.keyring().reseal(context, sealed);
  }

  async rotate(): Promise<{ keyId: string; wrapped: string | null }> {
    const ring = this.keyring();
    ring.rotate();
    await this.log.append({ action: 'rotate', keys: [ring.activeId] });
    return { keyId: ring.activeId, wrapped: await this.keys!.save(ring) };
  }

  async prune(used: Set<string>): Promise<{ dropped: string[]; wrapped: string | null }> {
    const ring = this.keyring();
    const dropped = ring.prune(used);
    if (!dropped.length) return { dropped, wrapped: null };
    await this.log.append({ action: 'prune', keys: dropped });
    return { dropped, wrapped: await this.keys!.save(ring) };
  }

  status(): { ready: boolean; mode: string; version: string; keyId: string | null; retired: string[]; node: string; logLength: number; needsCredentials: boolean; needsSettings: boolean } {
    const mode = this.keys?.mode ?? 'nitro';
    return {
      ready: this.ready,
      mode,
      version: this.version,
      keyId: this.ring?.activeId ?? null,
      retired: this.ring?.retiredIds() ?? [],
      node: this.log.nodeId,
      logLength: this.log.length,
      needsCredentials: mode !== 'file' && !this.credentials,
      needsSettings: !this.keys,
    };
  }

  /**
   * What a verifier checks: an attestation document (in an enclave) over the node's log key and the nonce they sent,
   * with the version and the key id in its user data.
   */
  async attestation(nonce?: Buffer): Promise<{ mode: string; version: string; node: string; logKey: string; keyId: string | null; logHead: string; settings: NodeSettings | null; document: string | null }> {
    const userData = Buffer.from(JSON.stringify({ version: this.version, keyId: this.ring?.activeId ?? null, settings: this.settings }));
    const doc = await this.attest(this.log.publicKeyDer(), nonce, userData);
    return { mode: this.keys?.mode ?? 'nitro', version: this.version, settings: this.settings, node: this.log.nodeId, logKey: this.log.publicKeyDer().toString('base64'), keyId: this.ring?.activeId ?? null, logHead: this.log.headHash, document: doc ? doc.toString('base64') : null };
  }

  logEntries(user?: number, limit?: number) {
    return this.log.entries(user, limit);
  }
}

/** The key ids of the sealed values the bot still keeps, for prune. */
export const keyIdsOf = (sealed: string[]) => new Set(sealed.map(sealedKeyId).filter((x): x is string => !!x));

async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > 256 * 1024) throw new NodeError(413, 'too large');
    chunks.push(c as Buffer);
  }
  if (!size) return {};
  const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!v || typeof v !== 'object') throw new NodeError(400, 'a JSON object');
  return v as Record<string, unknown>;
}

const str = (v: unknown, name: string): string => {
  if (typeof v !== 'string' || !v) throw new NodeError(400, `${name} is missing`);
  return v;
};

/** The node's API, plain JSON over HTTP on a port only the bot reaches (a Docker network, or vsock from the host). */
export function handler(node: VaultNode): (req: IncomingMessage, res: ServerResponse) => void {
  return (req, res) => {
    const send = (status: number, v: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(v));
    };
    (async () => {
      const url = new URL(req.url ?? '/', 'http://node');
      const route = `${req.method} ${url.pathname}`;
      if (route === 'GET /health') return send(200, node.status());
      if (route === 'GET /attestation') {
        const n = url.searchParams.get('nonce');
        if (n && !/^[0-9a-f]{2,128}$/i.test(n)) throw new NodeError(400, 'nonce is hex, at most 64 bytes');
        return send(200, await node.attestation(n ? Buffer.from(n, 'hex') : undefined));
      }
      if (route === 'GET /log') {
        const u = url.searchParams.get('user');
        return send(200, { node: node.status().node, entries: node.logEntries(u ? Number(u) : undefined, Math.min(Number(url.searchParams.get('limit')) || 100, 2000)) });
      }
      if (req.method !== 'POST') throw new NodeError(404, 'no such call');
      const b = await body(req);
      switch (url.pathname) {
        case '/credentials': {
          node.credentials = { accessKeyId: str(b.accessKeyId, 'accessKeyId'), secretAccessKey: str(b.secretAccessKey, 'secretAccessKey'), ...(typeof b.sessionToken === 'string' && b.sessionToken ? { sessionToken: b.sessionToken } : {}) };
          return send(200, { ok: true });
        }
        case '/configure':
          node.configure(b as unknown as NodeSettings);
          return send(200, node.status());
        case '/unlock':
          return send(200, { wrapped: await node.unlock(typeof b.wrapped === 'string' && b.wrapped ? b.wrapped : undefined), ...node.status() });
        case '/seal':
          return send(200, { sealed: await node.seal(str(b.context, 'context'), b.value, (b.shape as Shape) ?? {}) });
        case '/release':
          return send(200, { value: await node.release(str(b.context, 'context'), str(b.sealed, 'sealed'), b.purpose as never) });
        case '/reseal':
          return send(200, { sealed: node.reseal(str(b.context, 'context'), str(b.sealed, 'sealed')) });
        case '/rotate':
          return send(200, await node.rotate());
        case '/prune':
          return send(200, await node.prune(new Set(Array.isArray(b.used) ? b.used.map(String) : [])));
      }
      throw new NodeError(404, 'no such call');
    })().catch((e: unknown) => send(e instanceof NodeError ? e.status : 500, { error: e instanceof Error ? e.message : String(e) }));
  };
}

export function serve(node: VaultNode, port: number, host: string): Server {
  return createServer(handler(node)).listen(port, host);
}

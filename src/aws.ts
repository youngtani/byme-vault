import { createHash, createHmac, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { request } from 'node:https';
import { openEnveloped } from './cms.ts';

/** AWS keys: from the node's environment (a container), or handed over by the host (an enclave has no IMDS). */
export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

const sha256 = (s: string | Buffer) => createHash('sha256').update(s).digest('hex');
const hmac = (k: Buffer | string, s: string) => createHmac('sha256', k).update(s, 'utf8').digest();

/** AWS Signature Version 4: the request's headers plus x-amz-date and authorization. */
export function sigv4(r: { method: string; path: string; query?: string; headers: Record<string, string>; body: string | Buffer; region: string; service: string; accessKeyId: string; secretAccessKey: string; now: Date }): Record<string, string> {
  const amzDate = r.now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const day = amzDate.slice(0, 8);
  const headers: Record<string, string> = { ...Object.fromEntries(Object.entries(r.headers).map(([k, v]) => [k.toLowerCase(), v.trim()])), 'x-amz-date': amzDate };
  const names = Object.keys(headers).sort();
  const canonical = [r.method, r.path, r.query ?? '', ...names.map((n) => `${n}:${headers[n]}`), '', names.join(';'), sha256(r.body)].join('\n');
  const scope = `${day}/${r.region}/${r.service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonical)].join('\n');
  const key = [r.region, r.service, 'aws4_request'].reduce<Buffer>((k, part) => hmac(k, part), hmac(`AWS4${r.secretAccessKey}`, day));
  const signature = createHmac('sha256', key).update(toSign, 'utf8').digest('hex');
  return { ...headers, authorization: `AWS4-HMAC-SHA256 Credential=${r.accessKeyId}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}` };
}

/**
 * Where an AWS host is reached. In a container, the host itself. In an enclave, which has no network, a local port
 * the bridge carries over vsock to the host's vsock-proxy for that AWS host: TLS still ends here, in the enclave,
 * checked against the AWS host's name, so the host only relays bytes it cannot read.
 */
export type Route = (host: string) => { address: string; port: number };
export const direct: Route = (host) => ({ address: host, port: 443 });

export interface HttpsResult {
  status: number;
  body: Buffer;
}

export function httpsCall(route: Route, host: string, method: string, path: string, headers: Record<string, string>, body: string | Buffer): Promise<HttpsResult> {
  const { address, port } = route(host);
  return new Promise((resolve, reject) => {
    const req = request({ host: address, port, servername: host, method, path, headers: { ...headers, host, 'content-length': String(Buffer.byteLength(body)) }, timeout: 15_000 }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error(`${host}: timed out`)));
    req.on('error', reject);
    req.end(body);
  });
}

export type Https = typeof httpsCall;

/**
 * An attestation document for a public key: from the Nitro Secure Module inside an enclave, null elsewhere (a
 * container has nothing to attest with).
 */
export type Attest = (publicKey: Buffer, nonce?: Buffer, userData?: Buffer) => Promise<Buffer | null>;

/** Every KMS call names what the key is for, so CloudTrail shows each one as the vault node's. */
const CONTEXT = { purpose: 'byme-vault-node' };

/**
 * The KMS calls the node needs. With an attestation (in an enclave) each call carries a Recipient: KMS answers with
 * the plaintext encrypted to a key only this enclave holds, and the key policy lets only an enclave with the published
 * measurements ask (kms:RecipientAttestation:PCR0). Without one (a container) KMS answers in plain text.
 */
export class Kms {
  private readonly region: string;
  private readonly keyId: string;
  private readonly creds: () => AwsCredentials | null;
  private readonly attest: Attest;
  private readonly route: Route;
  private readonly https: Https;
  private readonly now: () => Date;

  constructor(o: { region: string; keyId: string; credentials: () => AwsCredentials | null; attest: Attest; route?: Route; https?: Https; now?: () => Date }) {
    this.region = o.region;
    this.keyId = o.keyId;
    this.creds = o.credentials;
    this.attest = o.attest;
    this.route = o.route ?? direct;
    this.https = o.https ?? httpsCall;
    this.now = o.now ?? (() => new Date());
  }

  async generateDataKey(): Promise<{ plaintext: Buffer; blob: string }> {
    const r = await this.call('GenerateDataKey', { KeyId: this.keyId, KeySpec: 'AES_256', EncryptionContext: CONTEXT });
    return { plaintext: r.plaintext, blob: String(r.raw.CiphertextBlob) };
  }

  async decrypt(blob: string): Promise<Buffer> {
    return (await this.call('Decrypt', { KeyId: this.keyId, CiphertextBlob: blob, EncryptionContext: CONTEXT })).plaintext;
  }

  private async call(action: string, body: Record<string, unknown>): Promise<{ plaintext: Buffer; raw: Record<string, unknown> }> {
    const creds = this.creds();
    if (!creds) throw new Error('No AWS credentials yet: the host has not handed them over.');
    // A key pair for this one call: KMS wraps the answer to its public half, which the attestation vouches for.
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const doc = await this.attest(pair.publicKey.export({ type: 'spki', format: 'der' }));
    const payload = JSON.stringify(doc ? { ...body, Recipient: { KeyEncryptionAlgorithm: 'RSAES_OAEP_SHA_256', AttestationDocument: doc.toString('base64') } } : body);
    const host = `kms.${this.region}.amazonaws.com`;
    const headers: Record<string, string> = { 'content-type': 'application/x-amz-json-1.1', host, 'x-amz-target': `TrentService.${action}` };
    if (creds.sessionToken) headers['x-amz-security-token'] = creds.sessionToken;
    const signed = sigv4({ method: 'POST', path: '/', headers, body: payload, region: this.region, service: 'kms', accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, now: this.now() });
    const res = await this.https(this.route, host, 'POST', '/', signed, payload);
    const text = res.body.toString('utf8');
    if (res.status !== 200) throw new Error(`KMS ${action}: HTTP ${res.status} ${text.slice(0, 300)}`);
    const raw = JSON.parse(text) as Record<string, unknown>;
    const plaintext = doc ? openEnveloped(Buffer.from(String(raw.CiphertextForRecipient), 'base64'), pair.privateKey as KeyObject) : Buffer.from(String(raw.Plaintext), 'base64');
    return { plaintext, raw };
  }
}

/**
 * Writes the node's log to an S3 bucket with Object Lock (compliance mode, a default retention set on the bucket):
 * once written, no one can change or delete an entry until the retention ends, the operator included.
 */
export class S3Log {
  private readonly o: { bucket: string; region: string; credentials: () => AwsCredentials | null; route?: Route; https?: Https; now?: () => Date };

  constructor(o: { bucket: string; region: string; credentials: () => AwsCredentials | null; route?: Route; https?: Https; now?: () => Date }) {
    this.o = o;
  }

  async put(name: string, body: string): Promise<void> {
    const creds = this.o.credentials();
    if (!creds) throw new Error('No AWS credentials for the log bucket yet.');
    const host = `${this.o.bucket}.s3.${this.o.region}.amazonaws.com`;
    const path = `/${name.split('/').map(encodeURIComponent).join('/')}`;
    // Object Lock buckets refuse a PUT without an integrity check.
    const headers: Record<string, string> = { host, 'content-type': 'application/json', 'content-md5': createHash('md5').update(body).digest('base64'), 'x-amz-content-sha256': sha256(body) };
    if (creds.sessionToken) headers['x-amz-security-token'] = creds.sessionToken;
    const signed = sigv4({ method: 'PUT', path, headers, body, region: this.o.region, service: 's3', accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, now: (this.o.now ?? (() => new Date()))() });
    const res = await (this.o.https ?? httpsCall)(this.o.route ?? direct, host, 'PUT', path, signed, body);
    if (res.status !== 200) throw new Error(`S3 log: HTTP ${res.status} ${res.body.toString('utf8').slice(0, 200)}`);
  }
}

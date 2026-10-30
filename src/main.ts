import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { Kms, S3Log, direct, type Attest, type Route } from './aws.ts';
import { FileSink, NodeLog, type LogSink } from './log.ts';
import { FileKeys, KmsKeys, VaultNode, serve, type NodeSettings } from './node.ts';

/**
 * Starts the vault node. Two ways to run it, the same program:
 *
 * - In an AWS Nitro Enclave (VAULT_NODE_NITRO=1, see enclave/README.md): no disk and no network. Its host tells it
 *   once which KMS key and log bucket to use (shown in its attestation); the keyring is wrapped by KMS for this
 *   enclave's measurements only, and the host keeps only that wrapped copy. AWS is reached over vsock through
 *   enclave-io, with TLS ending here.
 * - As a container next to the bot (docker-compose service "vault"): its own volume, and KMS if configured. No
 *   hardware isolation, but the bot no longer holds the key, and every release is in a log the bot cannot rewrite.
 */
const env = process.env;
const nitro = env.VAULT_NODE_NITRO === '1';
const dir = env.VAULT_NODE_DIR || null;
const version = env.BYME_VAULT_VERSION || 'dev';

/** In the enclave, each AWS host has a local port that enclave-io carries to the host's vsock-proxy for it. */
const route: Route = nitro
  ? (host) => {
      if (host.startsWith('kms.')) return { address: '127.0.0.1', port: 8443 };
      if (host.includes('.s3.')) return { address: '127.0.0.1', port: 8444 };
      throw new Error(`no route to ${host} from the enclave`);
    }
  : direct;

const attest: Attest = nitro
  ? (publicKey, nonce, userData) =>
      new Promise((resolve, reject) => {
        const args = ['attest', '--public-key', publicKey.toString('hex'), ...(nonce ? ['--nonce', nonce.toString('hex')] : []), ...(userData ? ['--user-data', userData.toString('hex')] : [])];
        execFile('/usr/local/bin/enclave-io', args, { maxBuffer: 64 * 1024 }, (err, stdout) => (err ? reject(err) : resolve(Buffer.from(stdout.trim(), 'base64'))));
      })
  : async () => null;

const credentials = env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY ? { accessKeyId: env.AWS_ACCESS_KEY_ID, secretAccessKey: env.AWS_SECRET_ACCESS_KEY, ...(env.AWS_SESSION_TOKEN ? { sessionToken: env.AWS_SESSION_TOKEN } : {}) } : null;
let node: VaultNode;
const creds = () => node.credentials;

/** The keyring's KMS wrap and the log's bucket, from the settings (the environment, or the enclave's host). */
const setup = (s: NodeSettings) => ({
  keys: new KmsKeys(new Kms({ region: s.region, keyId: s.kmsKeyId, credentials: creds, attest, route }), dir, nitro),
  sinks: s.logBucket ? [{ write: (e, signed) => new S3Log({ bucket: s.logBucket!, region: s.region, credentials: creds, route }).put(`${e.node}/${String(e.seq).padStart(10, '0')}.json`, JSON.stringify(signed)) } satisfies LogSink] : [],
});

const sinks: LogSink[] = dir ? [new FileSink(join(dir, 'log.jsonl'))] : [];
const log = new NodeLog(sinks);
if (nitro) {
  node = new VaultNode({ setup, log, attest, version, credentials });
} else if (env.VAULT_NODE_KMS_KEY_ID) {
  const made = setup({ kmsKeyId: env.VAULT_NODE_KMS_KEY_ID, region: env.AWS_REGION || 'ap-northeast-2', ...(env.VAULT_NODE_LOG_BUCKET ? { logBucket: env.VAULT_NODE_LOG_BUCKET } : {}) });
  made.sinks.forEach((s) => log.addSink(s));
  node = new VaultNode({ keys: made.keys, log, attest, version, credentials });
} else {
  if (!dir) throw new Error('Set VAULT_NODE_DIR (a volume of its own), VAULT_NODE_KMS_KEY_ID, or VAULT_NODE_NITRO=1.');
  node = new VaultNode({ keys: new FileKeys(dir), log, attest, version, credentials });
}
if (!dir && !nitro && !env.VAULT_NODE_LOG_BUCKET) console.warn('vault node: the log is kept in memory only (set VAULT_NODE_DIR or VAULT_NODE_LOG_BUCKET)');

const port = Number(env.VAULT_NODE_PORT || 7070);
serve(node, port, env.VAULT_NODE_HOST || (nitro ? '127.0.0.1' : '0.0.0.0'));
console.log(`vault node ${version} (${nitro ? 'nitro enclave' : env.VAULT_NODE_KMS_KEY_ID ? 'kms' : 'file'}) on :${port}`);

// A node that keeps its own keyring opens it now; one whose host keeps it (an enclave) waits for /configure and /unlock.
if (!nitro && dir && (!env.VAULT_NODE_KMS_KEY_ID || credentials)) {
  node.unlock().catch((e) => console.error(`vault node: not unlocked: ${e instanceof Error ? e.message : e}`));
}

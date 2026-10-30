import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { verifyAttestation } from './attestation.ts';
import { checkChain, type SignedEntry } from './log.ts';

/**
 * Checks that the vault node Byme runs is the published build, from anywhere:
 *
 *   enclave/build.sh                       (the same commit; writes enclave/out/measurements.json)
 *   node --experimental-strip-types enclave/src/verify.ts https://<byme address> enclave/out/measurements.json
 *
 * It sends a fresh nonce to <address>/vault/attestation and checks the answer: signed by an AWS Nitro Enclave
 * (certificate chain up to AWS's root), not in debug mode, PCR0-2 equal to your own build's, your nonce in it (not a
 * replay), and the node's log key in it (so every log entry signed with that key came from this enclave).
 * Exit code 0 = it matches, 1 = it does not, 2 = no answer.
 */
async function main(): Promise<number> {
  const [base, measurementsFile] = process.argv.slice(2);
  if (!base || !measurementsFile) {
    console.error('usage: verify.ts <https://byme address> <measurements.json>');
    return 2;
  }
  const m = JSON.parse(readFileSync(measurementsFile, 'utf8')) as { version?: string; PCR0: string; PCR1: string; PCR2: string };
  const nonce = randomBytes(32);
  let a: { document: string | null; logKey: string; version: string; settings: unknown; node: string; mode: string };
  try {
    const res = await fetch(`${base.replace(/\/+$/, '')}/vault/attestation?nonce=${nonce.toString('hex')}`);
    a = (await res.json()) as typeof a;
    if (!res.ok) throw new Error(JSON.stringify(a));
  } catch (e) {
    console.error(`no answer: ${e instanceof Error ? e.message : e}`);
    return 2;
  }
  if (!a.document) {
    console.log(`✗ the node runs as "${a.mode}", not in a Nitro Enclave: there is nothing to attest.`);
    return 1;
  }
  try {
    const doc = verifyAttestation(Buffer.from(a.document, 'base64'), { nonce, pcrs: { 0: m.PCR0, 1: m.PCR1, 2: m.PCR2 } });
    if (!doc.publicKey?.equals(Buffer.from(a.logKey, 'base64'))) throw new Error('the log key it shows is not the one in its attestation');
    const user = doc.userData ? JSON.parse(doc.userData.toString('utf8')) : {};
    if (m.version && user.version !== m.version) throw new Error(`it says version ${user.version}, your build is ${m.version}`);
    console.log(`✓ Byme's vault node is build ${user.version} in a real Nitro Enclave (${doc.moduleId}), measured ${new Date(doc.timestamp).toISOString()}.`);
    console.log(`  PCR0 ${doc.pcrs[0]}\n  PCR1 ${doc.pcrs[1]}\n  PCR2 ${doc.pcrs[2]}`);
    console.log(`  Its settings (KMS key, log bucket): ${JSON.stringify(user.settings)}`);
    console.log(`  Log key (node ${a.node}): ${a.logKey}`);
    return 0;
  } catch (e) {
    console.log(`✗ ${e instanceof Error ? e.message : e}`);
    return 1;
  }
}

/** A log's entries (one JSON per line, as the node writes them to its bucket) checked against its key. */
export function checkLogFile(file: string, logKeyBase64: string) {
  const entries = readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as SignedEntry);
  return checkChain(entries, Buffer.from(logKeyBase64, 'base64'));
}

if (import.meta.url === `file://${process.argv[1]}`) process.exit(await main());

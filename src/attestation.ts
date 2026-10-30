import { X509Certificate, createHash, verify } from 'node:crypto';
import { decodeCbor, encodeCbor, type Cbor } from './cbor.ts';

/**
 * Checks an AWS Nitro Enclaves attestation document: what a running vault node hands out at /attestation, so anyone
 * can see that the program holding the vault key is the published one (its measurements, PCR0-2, are what
 * build.sh prints for that commit) and that it runs in a real enclave, not in debug mode.
 *
 * The document is a COSE_Sign1 (RFC 9052) signed with ES384 by a certificate that chains up to AWS's Nitro
 * Enclaves root (pinned below by its SHA-256 fingerprint, from
 * https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip).
 */
export const AWS_NITRO_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
`;
export const AWS_NITRO_ROOT_SHA256 = '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b';

export interface Attested {
  moduleId: string;
  /** Milliseconds since 1970, by the enclave's clock. */
  timestamp: number;
  /** PCR index → hex. */
  pcrs: Record<number, string>;
  publicKey: Buffer | null;
  userData: Buffer | null;
  nonce: Buffer | null;
}

export interface VerifyOptions {
  /** PCR0, PCR1, PCR2 of the published build (measurements.json); left out = not compared. */
  pcrs?: Partial<Record<0 | 1 | 2, string>>;
  /** The nonce the verifier sent; left out = not compared. */
  nonce?: Buffer;
  /** The root the chain must end at (tests); defaults to AWS's. */
  rootPem?: string;
  /** The time the certificates must be valid at; defaults to the document's own timestamp. */
  at?: Date;
}

const field = (m: Map<Cbor, Cbor>, k: string) => m.get(k);
const bytes = (v: Cbor): Buffer | null => (Buffer.isBuffer(v) ? v : null);

/** The document's contents if every check passes; throws with the reason otherwise. */
export function verifyAttestation(doc: Buffer, opts: VerifyOptions = {}): Attested {
  let cose = decodeCbor(doc);
  if (cose && typeof cose === 'object' && 'tag' in cose) cose = cose.value;
  if (!Array.isArray(cose) || cose.length !== 4) throw new Error('not a COSE_Sign1 document');
  const [protectedHdr, , payloadBytes, signature] = cose;
  if (!Buffer.isBuffer(protectedHdr) || !Buffer.isBuffer(payloadBytes) || !Buffer.isBuffer(signature)) throw new Error('COSE_Sign1 parts are not byte strings');
  const hdr = decodeCbor(protectedHdr);
  if (!(hdr instanceof Map) || hdr.get(1) !== -35) throw new Error('not signed with ES384');
  const payload = decodeCbor(payloadBytes);
  if (!(payload instanceof Map)) throw new Error('the payload is not a map');
  if (field(payload, 'digest') !== 'SHA384') throw new Error('PCRs are not SHA384');

  const timestamp = Number(field(payload, 'timestamp'));
  const at = opts.at ?? new Date(timestamp);
  const bundle = field(payload, 'cabundle');
  const leafDer = bytes(field(payload, 'certificate') ?? null);
  if (!Array.isArray(bundle) || !bundle.length || !leafDer) throw new Error('no certificate chain');
  const root = new X509Certificate(opts.rootPem ?? AWS_NITRO_ROOT_PEM);
  if (!opts.rootPem && createHash('sha256').update(root.raw).digest('hex') !== AWS_NITRO_ROOT_SHA256) throw new Error('the pinned root is not AWS Nitro Enclaves Root-G1');
  const chain = bundle.map((c) => {
    const b = bytes(c);
    if (!b) throw new Error('a certificate in the bundle is not bytes');
    return new X509Certificate(b);
  });
  if (!chain[0].raw.equals(root.raw)) throw new Error('the chain does not start at the AWS Nitro root');
  const leaf = new X509Certificate(leafDer);
  const all = [...chain, leaf];
  for (let i = 0; i < all.length; i++) {
    const c = all[i];
    if (at < new Date(c.validFrom) || at > new Date(c.validTo)) throw new Error(`certificate ${i} is not valid at ${at.toISOString()}`);
    if (i === 0) continue;
    const issuer = all[i - 1];
    if (!c.checkIssued(issuer) || !c.verify(issuer.publicKey)) throw new Error(`certificate ${i} is not signed by the one before it`);
  }

  const sigStructure = encodeCbor(['Signature1', protectedHdr, Buffer.alloc(0), payloadBytes]);
  if (!verify('sha384', sigStructure, { key: leaf.publicKey, dsaEncoding: 'ieee-p1363' }, signature)) throw new Error('the signature does not match the document');

  const pcrMap = field(payload, 'pcrs');
  if (!(pcrMap instanceof Map)) throw new Error('no PCRs');
  const pcrs: Record<number, string> = {};
  for (const [k, v] of pcrMap) if (Buffer.isBuffer(v)) pcrs[Number(k)] = v.toString('hex');
  for (const i of [0, 1, 2]) {
    if (!pcrs[i] || /^0+$/.test(pcrs[i])) throw new Error(`PCR${i} is empty: the enclave runs in debug mode or was not measured`);
    const want = opts.pcrs?.[i as 0 | 1 | 2];
    if (want && want.toLowerCase() !== pcrs[i]) throw new Error(`PCR${i} is not the published build's (${pcrs[i].slice(0, 16)}… ≠ ${want.slice(0, 16)}…)`);
  }
  const nonce = bytes(field(payload, 'nonce') ?? null);
  if (opts.nonce && (!nonce || !nonce.equals(opts.nonce))) throw new Error('the nonce is not the one sent: a replayed document');
  return {
    moduleId: String(field(payload, 'module_id') ?? ''),
    timestamp,
    pcrs,
    publicKey: bytes(field(payload, 'public_key') ?? null),
    userData: bytes(field(payload, 'user_data') ?? null),
    nonce,
  };
}

import { constants, createDecipheriv, privateDecrypt, type KeyObject } from 'node:crypto';

/**
 * Opens what AWS KMS returns to an attested enclave (CiphertextForRecipient): a CMS EnvelopedData (RFC 5652) whose
 * content-encryption key is wrapped with RSAES-OAEP-SHA256 to the public key the enclave put in its attestation
 * document, and whose content (the KMS plaintext) is AES-256-CBC. Only the enclave holds the RSA private key, so the
 * host that relays the answer cannot read it. KMS writes BER (indefinite lengths, chunked octet strings): read both.
 */
interface Node {
  tag: number;
  constructed: boolean;
  /** Primitive: the content. */
  value: Buffer;
  /** Constructed: the children. */
  children: Node[];
}

function parse(buf: Buffer, at: number): [Node, number] {
  const id = buf[at++];
  const constructed = (id & 0x20) !== 0;
  let tag = id & 0x1f;
  if (tag === 0x1f) {
    tag = 0;
    let b: number;
    do {
      b = buf[at++];
      tag = (tag << 7) | (b & 0x7f);
    } while (b & 0x80);
  }
  tag |= id & 0xc0 ? (id & 0xc0) << 8 : 0; // keep the class apart from universal tags
  let len = buf[at++];
  if (len === 0x80) {
    // Indefinite: children until the end-of-contents marker 00 00.
    const children: Node[] = [];
    while (!(buf[at] === 0 && buf[at + 1] === 0)) {
      const [c, next] = parse(buf, at);
      children.push(c);
      at = next;
    }
    return [{ tag, constructed: true, value: Buffer.alloc(0), children }, at + 2];
  }
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[at++];
  }
  const end = at + len;
  if (end > buf.length) throw new Error('CMS: truncated');
  if (!constructed) return [{ tag, constructed, value: buf.subarray(at, end), children: [] }, end];
  const children: Node[] = [];
  let p = at;
  while (p < end) {
    const [c, next] = parse(buf, p);
    children.push(c);
    p = next;
  }
  return [{ tag, constructed, value: Buffer.alloc(0), children }, end];
}

/** An OCTET STRING's bytes, joined when BER cut it into chunks. */
const octets = (n: Node): Buffer => (n.constructed ? Buffer.concat(n.children.map(octets)) : n.value);

const oid = (n: Node): string => {
  const b = n.value;
  const out = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      out.push(v);
      v = 0;
    }
  }
  return out.join('.');
};

const ENVELOPED = '1.2.840.113549.1.7.3';
const RSA_OAEP = '1.2.840.113549.1.1.7';
const AES256_CBC = '2.16.840.1.101.3.4.1.42';
const CONTEXT_0 = 0x8000; // [0], context-specific

/** The plaintext inside a CMS EnvelopedData for one RSA-OAEP-SHA256 recipient and AES-256-CBC content. */
export function openEnveloped(der: Buffer, key: KeyObject): Buffer {
  const [info] = parse(der, 0);
  if (oid(info.children[0]) !== ENVELOPED) throw new Error('CMS: not EnvelopedData');
  const env = info.children[1].children[0];
  // version, [0] originatorInfo?, recipientInfos, encryptedContentInfo, ...
  const rest = env.children.slice(1).filter((c) => c.tag !== CONTEXT_0);
  const [recipients, content] = rest;
  const ktri = recipients.children[0];
  // version, rid, keyEncryptionAlgorithm, encryptedKey
  const keyAlg = ktri.children[2];
  if (oid(keyAlg.children[0]) !== RSA_OAEP) throw new Error('CMS: the key is not wrapped with RSA-OAEP');
  const cek = privateDecrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, octets(ktri.children[3]));
  const alg = content.children[1];
  if (oid(alg.children[0]) !== AES256_CBC) throw new Error('CMS: the content is not AES-256-CBC');
  const iv = octets(alg.children[1]);
  const body = octets(content.children.find((c) => c.tag === CONTEXT_0)!);
  const d = createDecipheriv('aes-256-cbc', cek, iv);
  return Buffer.concat([d.update(body), d.final()]);
}

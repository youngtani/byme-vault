/**
 * The small part of CBOR (RFC 8949) a Nitro attestation document uses: unsigned and negative integers, byte and text
 * strings, arrays, maps, tags, null/true/false. Definite lengths only, which is what the Nitro Secure Module writes.
 */
export type Cbor = number | bigint | Buffer | string | Cbor[] | Map<Cbor, Cbor> | boolean | null | undefined | { tag: number; value: Cbor };

export function decodeCbor(buf: Buffer): Cbor {
  const [v, end] = item(buf, 0);
  if (end !== buf.length) throw new Error('CBOR: bytes after the item');
  return v;
}

function length(buf: Buffer, at: number, info: number): [number | bigint, number] {
  if (info < 24) return [info, at];
  if (info === 24) return [buf.readUInt8(at), at + 1];
  if (info === 25) return [buf.readUInt16BE(at), at + 2];
  if (info === 26) return [buf.readUInt32BE(at), at + 4];
  if (info === 27) {
    const n = buf.readBigUInt64BE(at);
    return [n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n, at + 8];
  }
  throw new Error('CBOR: indefinite or reserved length');
}

function item(buf: Buffer, at: number): [Cbor, number] {
  if (at >= buf.length) throw new Error('CBOR: truncated');
  const head = buf[at];
  const major = head >> 5;
  const [n, next] = length(buf, at + 1, head & 31);
  const count = Number(n);
  switch (major) {
    case 0:
      return [n, next];
    case 1:
      return [typeof n === 'bigint' ? -1n - n : -1 - n, next];
    case 2:
    case 3: {
      if (next + count > buf.length) throw new Error('CBOR: truncated string');
      const bytes = buf.subarray(next, next + count);
      return [major === 2 ? Buffer.from(bytes) : bytes.toString('utf8'), next + count];
    }
    case 4: {
      const out: Cbor[] = [];
      let p = next;
      for (let i = 0; i < count; i++) {
        const [v, q] = item(buf, p);
        out.push(v);
        p = q;
      }
      return [out, p];
    }
    case 5: {
      const out = new Map<Cbor, Cbor>();
      let p = next;
      for (let i = 0; i < count; i++) {
        const [k, q] = item(buf, p);
        const [v, r] = item(buf, q);
        out.set(k, v);
        p = r;
      }
      return [out, p];
    }
    case 6: {
      const [v, p] = item(buf, next);
      return [{ tag: count, value: v }, p];
    }
    default: {
      const info = head & 31;
      if (info === 20) return [false, at + 1];
      if (info === 21) return [true, at + 1];
      if (info === 22) return [null, at + 1];
      if (info === 23) return [undefined, at + 1];
      throw new Error('CBOR: floats and other simple values are not used here');
    }
  }
}

function headOf(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  if (n < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

export function encodeCbor(v: Cbor): Buffer {
  if (v === null) return Buffer.from([0xf6]);
  if (v === undefined) return Buffer.from([0xf7]);
  if (v === true) return Buffer.from([0xf5]);
  if (v === false) return Buffer.from([0xf4]);
  if (typeof v === 'number' || typeof v === 'bigint') {
    const n = Number(v);
    if (!Number.isSafeInteger(n)) throw new Error('CBOR: only safe integers');
    if (n >= 0) {
      if (n > 0xffffffff) {
        const b = Buffer.alloc(9);
        b[0] = 27;
        b.writeBigUInt64BE(BigInt(n), 1);
        return b;
      }
      return headOf(0, n);
    }
    return headOf(1, -1 - n);
  }
  if (Buffer.isBuffer(v)) return Buffer.concat([headOf(2, v.length), v]);
  if (typeof v === 'string') {
    const b = Buffer.from(v, 'utf8');
    return Buffer.concat([headOf(3, b.length), b]);
  }
  if (Array.isArray(v)) return Buffer.concat([headOf(4, v.length), ...v.map(encodeCbor)]);
  if (v instanceof Map) return Buffer.concat([headOf(5, v.size), ...[...v].flatMap(([k, x]) => [encodeCbor(k), encodeCbor(x)])]);
  return Buffer.concat([headOf(6, v.tag), encodeCbor(v.value)]);
}

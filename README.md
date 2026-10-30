# The vault node

The one program that can open the user's most sensitive details: site passwords, the card, payment PINs and
본인인증 details. Modeled on Pickle's credential enclave (github.com/pickle-com/credential-enclave): the bot can have a
value typed for the user, but cannot read the vault on its own, and anyone can check which program holds the key.

## What it does

- **seal**: the bot hands it a value and its *shape* (which fields a card has, what kind of ID a login uses); it
  returns the value sealed with AES-256-GCM under a key only it holds, bound to `shop_vault/<user>/<entry>` and to the
  shape. The bot stores that and reads the shape without opening anything.
- **release**: when a run is about to type a value, the bot asks for it, naming the order and the site. The node
  writes that to its log first and answers only once the log has it.
- **log**: every seal, release, rotation and start, signed with a key made inside the node at boot and chained (each
  entry has the hash of the one before). No value is ever in it. With `VAULT_NODE_LOG_BUCKET` each entry goes to an
  S3 bucket with Object Lock before the act, so nobody, Byme included, can delete or change one for a year.
- **rotate / reseal / prune**: a new key, values sealed again inside the node (they never leave it), old keys dropped.
- **attestation**: in a Nitro Enclave, a document signed by AWS's Nitro hardware stating the measurements of the
  program running (PCR0-2), the node's log key, its KMS key and log bucket, and the nonce the asker sent.

Code: `src/` (TypeScript, Node's built-in modules only, no npm packages), `io/` (a small Rust tool for the Nitro
Secure Module and vsock). The bot's side (`src/shop/vaultnode.ts`) and the server scripts named below are in Byme's
main repository, which is not public.

## This repository

[github.com/youngtani/byme-vault](https://github.com/youngtani/byme-vault) is the `enclave/` folder of Byme's main
repository, copied here on every change that reaches its main branch, after a check that nothing secret or internal
is in it (`deploy/vault-public-check.sh` there). Each copy is one commit tagged `vault-<tree>`: the first 12
characters of the folder's git tree, which is also the build's name (`version`) that the running node reports. The
folder here and there is the same git tree, so a build here measures exactly like the build Byme runs.

## Where it runs

| | The key is in | Who can read the vault |
| --- | --- | --- |
| No `SHOP_VAULT_NODE_URL` (development) | the bot's own process | anyone with the bot's process or its `keys/` volume |
| **docker-compose service `vault`** (the default now) | the node's container and its `vault-node` volume | the bot cannot (no key, every release logged where it cannot rewrite it); root on the server can |
| **Nitro Enclave on EC2** | enclave memory; wrapped by KMS for these measurements only | nobody: not the bot, not root on the host, not Byme. Values leave only by a logged release |

In every case a value released for a run is typed into the page by the bot's browser code (as with any password
manager): the chat model never sees it, and runs only get the values of their own order.

## Verifying the running node (anyone)

Needs git, Docker with buildx, Node 22.6 or later, and a machine of the server's CPU kind (arm64, e.g. an Apple
silicon Mac or a Graviton instance, for Byme's Graviton server). `nitro-cli` is not needed: without it `build.sh` runs
it from an Amazon Linux container.

```sh
curl -s https://bymeai.io/vault/attestation | grep -o '"version":"[^"]*"'   # the build the node runs, vault-<tree>
git clone https://github.com/youngtani/byme-vault && cd byme-vault
git checkout vault-<tree>                         # the version above
./build.sh                                        # writes out/measurements.json (PCR0, PCR1, PCR2)
node --experimental-strip-types src/verify.ts https://bymeai.io out/measurements.json
```

`verify.ts` sends a fresh nonce to `/vault/attestation` and checks: the AWS certificate chain (root pinned by its
SHA-256), the signature, not debug mode, PCR0-2 equal to your build's, the version equal to your build's, your nonce
(no replay), and that the log key it shows is the one in the attested document.

### Why the same code gives the same PCR0

PCR0 is a hash of the whole enclave image, so every byte has to come out the same on any machine:

- base images pinned by their digest (`Dockerfile`), Rust crates by `io/Cargo.lock` (`cargo build --locked`);
- no npm packages at all: the node is Node's built-in modules plus `src/`;
- every file in the image stamped with one fixed time (`SOURCE_DATE_EPOCH`, `rewrite-timestamp=true`), and the Rust
  binary built without build ids or local paths;
- the build named by the folder's git tree (not a commit or a date), so the name inside the image is the same here
  and in Byme's repository.

Byme's CI builds every change twice on each CPU kind, on different machines, and fails if the two do not measure the
same; its `measurements.json` files are kept with each run.

## Moving it into a Nitro Enclave (once)

The whole move, from the Lightsail server to EC2, is scripted in Byme's main repository (`deploy/move-to-ec2.sh`,
run on the old server, which runs `deploy/ec2-setup.sh` on the new one; the owner's console steps in
`docs/ec2-move.md`). What the scripts set up:

- **EC2 in Seoul**, Amazon Linux 2023, Graviton `m6g.large` (2 vCPU, 8 GiB: the bot, and a 1-vCPU enclave), *Nitro
  Enclave: enabled* at launch (Lightsail cannot run enclaves; Intel/AMD needs 4 vCPU), an Elastic IP.
- **AWS keys from the instance's IAM role**, none in `.env`: the bot reads the role's short-lived keys from the
  instance metadata (IMDSv2, hop limit 2) and hands them to the enclave, again before they expire
  (`instanceRoleKeys` in `src/shop/vaultnode.ts`). The role has no permissions of its own.
- **KMS key** `alias/byme-vault-node`, whose policy (written by `ec2-setup.sh prepare`, with this build's PCR0 and the
  role's ARN) lets the role decrypt only from inside an enclave with a listed PCR0:
  ```json
  { "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::<account>:role/byme-server" },
    "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*",
    "Condition": { "StringEqualsIgnoreCase": { "kms:RecipientAttestation:PCR0": ["<PCR0>"] },
                   "StringEquals": { "kms:EncryptionContext:purpose": "byme-vault-node" } } }
  ```
  plus `kms:DescribeKey`/`kms:GetKeyPolicy` without a condition (the server can see which builds are allowed, nothing
  more). A call without an enclave's attestation has no PCR0, so the condition fails: the role alone opens nothing.
- **Log bucket** (optional, recommended) `byme-vault-log-<account>`: Object Lock, default retention *Compliance, 365
  days*, the role allowed only `s3:PutObject` (and `s3:ListBucket`, to see that it is there).
- **The enclave as systemd services** (`run-host.sh`): the enclave (`out/live.eif`), the vsock proxies to KMS and the
  bucket, and the bot's way in on Docker's bridge address only. They come back after a reboot.
- **Moving the values**: the old server's `vault` container (with its volume) runs once more next to the enclave
  (`COMPOSE_PROFILES=sidecar`, `SHOP_VAULT_NODE_PREVIOUS_URL=http://vault:7070`); at start the bot asks it for each
  value the enclave cannot open (logged there as "move to the new vault node") and seals it in the enclave. Only when
  `npm run vault-check` says none is waiting, and the attestation verified, are the container and its volume removed.
  The bot keeps only `keys/node.wrapped` (useless without the enclave). `/vault` shows "nitro".
- **A new enclave build** has a new PCR0. Auto-update (`deploy/enclave-update.sh`) builds it and asks the owner, once,
  to add its PCR0 to the key policy; it runs it as soon as the policy lists it (the old build keeps running until
  then), verifies the attestation and says so. The key policy is the one thing still in the AWS account owner's hands:
  publish its PCR0 list with each release so users can see which builds were allowed.

## License

MIT, see [LICENSE](https://github.com/youngtani/byme-vault/blob/main/LICENSE). Questions or a finding: ahnyuofm@gmail.com (Byme's privacy officer).

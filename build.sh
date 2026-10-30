#!/usr/bin/env bash
# Builds the vault node's Nitro Enclave image from the current commit and prints its measurements.
#   enclave/build.sh            -> enclave/out/enclave.eif, enclave/out/measurements.json
# The same files give the same PCR0/1/2 on any machine of the same CPU kind (arm64 for Graviton, x86_64 otherwise):
# base images pinned by digest, Rust crates by Cargo.lock, every file stamped with one fixed time. The build is named
# by this folder's git tree, not by a commit, so the main repository's enclave/ and the public copy of it
# (github.com/youngtani/byme-vault, where it is the whole repository) build the same thing under the same name.
# Needs git, Docker with buildx, and nitro-cli (on the EC2 host: dnf install -y aws-nitro-enclaves-cli-devel); without
# nitro-cli it runs it from an Amazon Linux container.
set -euo pipefail
cd "$(dirname "$0")"
[ -z "$(git status --porcelain -- .)" ] || { echo "enclave/ has uncommitted changes: commit first, so the build is the commit's" >&2; exit 1; }
COMMIT="$(git rev-parse HEAD)"
TREE="$(git rev-parse HEAD:./)"
TAG="vault-${TREE:0:12}"
EPOCH=1767225600 # 2026-01-01T00:00:00Z
mkdir -p out
# A registry that answers "too many requests" now and then gets three tries.
for try in 1 2 3; do
  docker buildx build \
    --build-arg BYME_VAULT_VERSION="$TAG" \
    --build-arg SOURCE_DATE_EPOCH="$EPOCH" \
    --output "type=docker,name=byme-vault:$TAG,rewrite-timestamp=true" \
    --provenance=false . && break
  [ "$try" = 3 ] && exit 1
  sleep $((try * 20))
done

if command -v nitro-cli >/dev/null; then
  nitro-cli build-enclave --docker-uri "byme-vault:$TAG" --output-file out/enclave.eif > out/build.json
else
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/out:/out" public.ecr.aws/amazonlinux/amazonlinux:2023 \
    sh -c "dnf install -y -q aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel >/dev/null && nitro-cli build-enclave --docker-uri byme-vault:$TAG --output-file /out/enclave.eif" > out/build.json
fi
python3 - "$TAG" "$COMMIT" "$TREE" <<'PY'
import json, sys
m = json.load(open('out/build.json'))['Measurements']
out = {'version': sys.argv[1], 'commit': sys.argv[2], 'tree': sys.argv[3], 'PCR0': m['PCR0'], 'PCR1': m['PCR1'], 'PCR2': m['PCR2']}
json.dump(out, open('out/measurements.json', 'w'), indent=2)
print(json.dumps(out, indent=2))
PY

#!/bin/sh
# Starts the vault node. In the enclave first: the loopback (down in a fresh enclave), the way in from the host
# (vsock 7070 -> 127.0.0.1:7070), and the ways out to AWS (127.0.0.1:8443 -> host vsock-proxy for KMS, 8444 for S3).
set -e
if [ "$VAULT_NODE_NITRO" = "1" ]; then
  /usr/local/bin/enclave-io lo-up
  /usr/local/bin/enclave-io vsock-to-tcp 7070 127.0.0.1:7070 &
  /usr/local/bin/enclave-io tcp-to-vsock 127.0.0.1:8443 3:8443 &
  /usr/local/bin/enclave-io tcp-to-vsock 127.0.0.1:8444 3:8444 &
fi
exec node --experimental-strip-types --disable-warning=ExperimentalWarning /node/src/main.ts

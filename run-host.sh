#!/usr/bin/env bash
# On the EC2 host (Amazon Linux 2023, Nitro Enclaves turned on for the instance): runs the vault node's enclave and
# the links around it as systemd services, so they come back after a reboot and a link that dies is restarted. The
# host only relays bytes: the node's key and the values it opens never leave the enclave except a value released for
# a run, to the bot.
#   sudo enclave/run-host.sh            (after enclave/build.sh: runs that build; again after each new build)
# The build it runs is copied to out/live.eif (and its measurements to out/live.json): a later build.sh does not
# change what starts after a reboot until this runs it. Settings from ../.env: SHOP_VAULT_NODE_LOG_BUCKET
# (optional), AWS_REGION (default ap-northeast-2).
set -euo pipefail
cd "$(dirname "$0")"
DIR="$PWD"
[ "$(id -u)" -eq 0 ] || { echo "run it with sudo" >&2; exit 1; }
[ -f out/enclave.eif ] && [ -f out/measurements.json ] || { echo "no build: run enclave/build.sh first" >&2; exit 1; }
setting() { grep -E "^$1=" ../.env 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' | tr -d "'" || true; }
REGION="$(setting AWS_REGION)"; REGION="${REGION:-ap-northeast-2}"
BUCKET="$(setting SHOP_VAULT_NODE_LOG_BUCKET)"
CID=16
CPUS="${VAULT_ENCLAVE_CPUS:-1}"
# nitro-cli wants about four times the image's size; never less than 1 GiB.
EIF_MIB=$(( $(stat -c %s out/enclave.eif) / 1048576 ))
MEM="${VAULT_ENCLAVE_MEMORY:-$(( (EIF_MIB * 4 / 256 + 1) * 256 ))}"
[ "$MEM" -ge 1024 ] || MEM=1024

# Once: the tools.
if ! command -v nitro-cli >/dev/null || ! command -v socat >/dev/null; then
  dnf install -y -q aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel socat
  usermod -aG ne "${SUDO_USER:-ec2-user}" || true
fi

# The enclave stops first: the allocator cannot change what it set aside while one runs.
systemctl stop byme-vault-enclave.service 2>/dev/null || true
nitro-cli terminate-enclave --all >/dev/null 2>&1 || true
cat > /etc/nitro_enclaves/allocator.yaml <<YAML
---
memory_mib: $MEM
cpu_count: $CPUS
YAML
systemctl enable -q nitro-enclaves-allocator.service
systemctl restart nitro-enclaves-allocator.service

# Only these AWS hosts may be reached from the enclave, each on its own vsock port.
{
  echo "allowlist:"
  echo "- {address: kms.${REGION}.amazonaws.com, port: 443}"
  [ -z "$BUCKET" ] || echo "- {address: ${BUCKET}.s3.${REGION}.amazonaws.com, port: 443}"
} > /etc/nitro_enclaves/vsock-proxy.yaml

cp out/enclave.eif out/live.eif.tmp && mv out/live.eif.tmp out/live.eif
cp out/measurements.json out/live.json

unit() { cat > "/etc/systemd/system/$1.service"; }
unit byme-vault-proxy-kms <<UNIT
[Unit]
Description=Byme vault node: the enclave's way to KMS (vsock 8443)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/vsock-proxy 8443 kms.${REGION}.amazonaws.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
if [ -n "$BUCKET" ]; then
  unit byme-vault-proxy-s3 <<UNIT
[Unit]
Description=Byme vault node: the enclave's way to its log bucket (vsock 8444)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/vsock-proxy 8444 ${BUCKET}.s3.${REGION}.amazonaws.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
else
  systemctl disable -q --now byme-vault-proxy-s3.service 2>/dev/null || true
  rm -f /etc/systemd/system/byme-vault-proxy-s3.service
fi
# The bot's way in: port 7070 on Docker's own bridge address only (the bot's container reaches it as
# host.docker.internal:7070; nothing outside the server can), to the enclave's vsock port 7070.
unit byme-vault-link <<'UNIT'
[Unit]
Description=Byme vault node: the bot's way in (docker0:7070 -> enclave vsock 7070)
After=docker.service
Requires=docker.service
[Service]
ExecStart=/bin/sh -c 'exec /usr/bin/socat TCP-LISTEN:7070,fork,reuseaddr,bind=$(ip -4 -o addr show docker0 | sed -E "s/.* inet ([0-9.]+).*/\1/") VSOCK-CONNECT:16:7070'
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
# The enclave itself, never in debug mode (a debug enclave's PCRs are zero and KMS refuses it).
unit byme-vault-enclave <<UNIT
[Unit]
Description=Byme vault node: the Nitro Enclave (out/live.eif)
After=nitro-enclaves-allocator.service byme-vault-proxy-kms.service
Requires=nitro-enclaves-allocator.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/bin/nitro-cli terminate-enclave --all
ExecStart=/usr/bin/nitro-cli run-enclave --eif-path ${DIR}/out/live.eif --cpu-count ${CPUS} --memory ${MEM} --enclave-cid ${CID}
ExecStop=/usr/bin/nitro-cli terminate-enclave --all
[Install]
WantedBy=multi-user.target
UNIT
# What run-host.sh started by hand before these services: gone, so two links never fight over a port.
pkill -f '^vsock-proxy 844[34]' 2>/dev/null || true
pkill -f '^socat TCP-LISTEN:7070' 2>/dev/null || true

systemctl daemon-reload
services="byme-vault-proxy-kms byme-vault-link byme-vault-enclave"
[ -z "$BUCKET" ] || services="byme-vault-proxy-s3 $services"
for s in $services; do systemctl enable -q "$s.service"; systemctl restart "$s.service"; done
nitro-cli describe-enclaves | grep -q '"State": "RUNNING"' || { echo "the enclave did not start:" >&2; journalctl -u byme-vault-enclave -n 30 --no-pager >&2; exit 1; }
echo "vault node enclave running (CID $CID, ${CPUS} vCPU, ${MEM} MiB). Measurements of this build:"
cat out/live.json

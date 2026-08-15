#!/usr/bin/env bash
# §5: install Incus in this Lima VM as a disposable nested test target, via
# the zabbly repo, then `incus admin init` a throwaway btrfs pool + a
# pinned-subnet bridge. Encodes §1's Incus-config gotchas at the substrate
# level (images:debian/12, not Ubuntu; btrfs-progs; pinned subnet, not auto).
#
# REQUIRES ROOT. This build VM's `agent` user has none (see NEEDS-HUMAN.md)
# so this script is written but not executed here — run it as root, once,
# on whatever host is actually standing up the nested Incus.
#
# Idempotent: safe to re-run; every step checks before acting.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi

# Keep these in sync with warden/profiles.py — they're the same substrate.
STORAGE_POOL="wardenpool"
BRIDGE="wardenbr0"
# MUST match warden/profiles.py BRIDGE_SUBNET (D21 moved it 100.89 -> 172.29; this script had drifted).
# warden's ensure_substrate() network_set()s the bridge to this value, so a mismatch means warden
# reconfigures the bridge's subnet out from under a running container. Keep the two in lockstep —
# same WARDEN_NESTED_BRIDGE_SUBNET override profiles.py reads, for the same reason (VANTAGE-PLAN.md:
# a nested wardenbr0 reusing the outer bridge's exact subnet locally shadows it inside the guest).
BRIDGE_SUBNET="${WARDEN_NESTED_BRIDGE_SUBNET:-172.29.0.1/24}"
POOL_SIZE="15GiB"

if ! command -v incus >/dev/null 2>&1; then
  echo "== installing incus (zabbly repo) =="
  . /etc/os-release
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc
  cat >/etc/apt/sources.list.d/zabbly-incus-stable.sources <<EOF
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: ${VERSION_CODENAME}
Components: main
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/zabbly.asc
EOF
  apt-get update
  # btrfs-progs explicitly — the storage pool driver needs it and it's not
  # pulled in by the incus package alone on a minimal image.
  #
  # --no-install-recommends: without it, incus's Recommends chain pulls a full mesa/LLVM/QEMU-SPICE
  # graphics+audio stack (libllvm15, mesa-vulkan-drivers, libgl1-mesa-dri, pocketsphinx-en-us,
  # libflite1, libmfx1 — measured on a real build: ~260MB) that a headless vantage VM, driven
  # entirely over `incus exec`/the API with no display ever attached, has no use for. If a future
  # `incus launch --vm` from inside the nested Incus needs QEMU's graphical console after all, this
  # is the line to revisit — nothing here currently exercises that path.
  apt-get install -y --no-install-recommends incus incus-client btrfs-progs
else
  echo "== incus already installed, skipping package step =="
fi

# Producer fully into a var, then grep a here-string — never `producer | grep -q` under
# `set -o pipefail`: grep -q exits at the first match and SIGPIPEs the producer, which pipefail
# then reports as 141, a false negative *caused by the match* (see DECISIONS D18). Harmless here
# only because the pool list is tiny; written safely so a larger producer can't reintroduce it.
existing_pools="$(incus storage list --format csv 2>/dev/null | cut -d, -f1)"
if grep -qx "${STORAGE_POOL}" <<<"${existing_pools}"; then
  echo "== storage pool ${STORAGE_POOL} already exists, skipping admin init =="
else
  echo "== incus admin init: throwaway btrfs pool + pinned bridge =="
  # Loop-backed btrfs via `size` — incus manages the image under its own storage-pools dir. A manual
  # `source:` image under /var/lib/incus is rejected by incus >= 7.x ("Only allowed source path ...").
  incus admin init --preseed <<PRESEED
storage_pools:
- name: ${STORAGE_POOL}
  driver: btrfs
  config:
    size: ${POOL_SIZE}
networks:
- name: ${BRIDGE}
  type: bridge
  config:
    ipv4.address: ${BRIDGE_SUBNET}
    ipv4.nat: "true"
    ipv6.address: none
profiles:
- name: default
  config: {}
  devices: {}
PRESEED
fi

echo "== verifying =="
incus storage list
incus network list
echo "incus ready: pool=${STORAGE_POOL} bridge=${BRIDGE} (${BRIDGE_SUBNET})"

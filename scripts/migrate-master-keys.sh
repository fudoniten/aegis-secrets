#!/usr/bin/env bash
# migrate-master-keys.sh
#
# For each host in build/hosts/, connects via SSH and converts the existing
# SSH host private key (at master-key.key-path from fudo-entities) into an
# age X25519 private key, storing the result at /state/aegis/master-key.
#
# Run from the deploy host (or any host with SSH root access to the fleet).
# Requires: nix, jq, ssh, ssh-to-age  (all present in the aegis devShell)
#
# Usage:
#   ./scripts/migrate-master-keys.sh [entities-path]
#
# If entities-path is not given, $AEGIS_ENTITIES is used (set automatically
# in the aegis devShell).

set -euo pipefail

ENTITIES_PATH="${1:-${AEGIS_ENTITIES:-}}"
if [[ -z "$ENTITIES_PATH" ]]; then
    echo "Usage: $0 <path-to-fudo-entities>" >&2
    echo "       Or run from within the aegis devShell (sets AEGIS_ENTITIES)." >&2
    exit 1
fi

# Check required tools
for cmd in nix jq ssh ssh-to-age; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found in PATH" >&2
        exit 1
    fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTS_DIR="$(dirname "$SCRIPT_DIR")/build/hosts"

TARGET_DIR="/state/aegis"
TARGET_KEY="${TARGET_DIR}/master-key"

SSH_TIMEOUT=10
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout="$SSH_TIMEOUT")

ok=()
unreachable=()
skipped=()
failed=()

# Temp file for local key conversion; cleaned up on exit
tmpkey=$(mktemp)
trap 'rm -f "$tmpkey" "${tmpkey}.age"' EXIT INT TERM
chmod 600 "$tmpkey"

for host_dir in "$HOSTS_DIR"/*/; do
    hostname="$(basename "$host_dir")"
    echo ""
    echo "==> ${hostname}"

    # --- Look up host in entities ---
    if ! host_json=$(nix eval --json \
            --extra-experimental-features "nix-command flakes" \
            "path:${ENTITIES_PATH}#entities.hosts.${hostname}" 2>/dev/null); then
        echo "    skip: not found in entities"
        skipped+=("${hostname}: not in entities")
        continue
    fi

    domain=$(printf '%s' "$host_json" | jq -r '.domain // empty')
    key_path=$(printf '%s' "$host_json" | jq -r '."master-key"."key-path" // empty')

    if [[ -z "$domain" ]]; then
        echo "    skip: no domain in entities"
        skipped+=("${hostname}: no domain")
        continue
    fi
    if [[ -z "$key_path" ]]; then
        echo "    skip: no master-key.key-path in entities"
        skipped+=("${hostname}: no master-key.key-path")
        continue
    fi

    fqdn="${hostname}.${domain}"
    echo "    fqdn:     ${fqdn}"
    echo "    key-path: ${key_path}"

    # --- Reachability check ---
    if ! ssh "${SSH_OPTS[@]}" "root@${fqdn}" true 2>/dev/null; then
        echo "    skip: unreachable (timeout or connection refused)"
        unreachable+=("${hostname} (${fqdn})")
        continue
    fi

    # --- Key type check ---
    key_info=$(ssh "${SSH_OPTS[@]}" "root@${fqdn}" \
        "ssh-keygen -l -f \"${key_path}\" 2>&1") || {
        echo "    FAIL: cannot inspect key at ${key_path}"
        failed+=("${hostname}: cannot inspect key")
        continue
    }

    if ! grep -qi 'ED25519' <<< "$key_info"; then
        key_type=$(awk '{print $NF}' <<< "$key_info" | tr -d '()')
        echo "    skip: key is ${key_type:-unknown}, not ED25519"
        echo "          ssh-to-age only supports ed25519; convert or replace this key manually"
        skipped+=("${hostname}: key type ${key_type:-unknown}")
        continue
    fi

    echo "    key type: ED25519 — converting to age X25519..."

    # --- Fetch private key, convert locally, write back ---

    # 1. Copy private key from host into a local temp file
    rm -f "$tmpkey" "${tmpkey}.age"
    touch "$tmpkey" && chmod 600 "$tmpkey"

    if ! ssh "${SSH_OPTS[@]}" "root@${fqdn}" "cat \"${key_path}\"" > "$tmpkey" 2>/dev/null; then
        echo "    FAIL: could not read ${key_path} from host"
        failed+=("${hostname}: could not read key")
        continue
    fi

    # 2. Convert ed25519 → age X25519 locally
    if ! ssh-to-age -private-key -i "$tmpkey" -o "${tmpkey}.age" 2>/dev/null; then
        echo "    FAIL: ssh-to-age conversion failed (is the key passphrase-protected?)"
        failed+=("${hostname}: conversion failed")
        continue
    fi

    # 3. Write the age key back to the host
    remote_write="mkdir -p \"${TARGET_DIR}\" \
        && chmod 700 \"${TARGET_DIR}\" \
        && cat > \"${TARGET_KEY}\" \
        && chmod 400 \"${TARGET_KEY}\""

    if ! cat "${tmpkey}.age" | ssh "${SSH_OPTS[@]}" "root@${fqdn}" "$remote_write" 2>/dev/null; then
        echo "    FAIL: could not write age key to ${TARGET_KEY}"
        failed+=("${hostname}: could not write key")
        continue
    fi

    rm -f "$tmpkey" "${tmpkey}.age"
    ok+=("${hostname}")
    echo "    OK: ${TARGET_KEY} written"
done

echo ""
echo "=============================="
echo "Summary"
echo "=============================="
printf "Converted    (%2d): %s\n" "${#ok[@]}"          "${ok[*]:----}"
printf "Unreachable  (%2d): %s\n" "${#unreachable[@]}" "${unreachable[*]:----}"
printf "Skipped      (%2d): %s\n" "${#skipped[@]}"     "${skipped[*]:----}"
printf "Failed       (%2d): %s\n" "${#failed[@]}"      "${failed[*]:----}"
echo ""

if [[ ${#failed[@]} -gt 0 ]]; then
    echo "Some hosts failed — check output above." >&2
    exit 1
fi

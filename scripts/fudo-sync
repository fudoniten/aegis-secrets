#!/usr/bin/env bash
# Sync fudo-nix-entities with aegis-secrets: initialize all hosts, roles, and build secrets.

set -euo pipefail

AEGIS_SYSTEM="${AEGIS_SYSTEM:-$(pwd)}"
: "${AEGIS_ENTITIES_JSON:?AEGIS_ENTITIES_JSON is not set — run this inside the dev shell}"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

warn()  { echo -e "${YELLOW}${*}${NC}" >&2; }
error() { echo -e "${RED}${BOLD}${*}${NC}" >&2; }
info()  { echo -e "${CYAN}${*}${NC}"; }
success() { echo -e "${GREEN}${*}${NC}"; }

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

aegis_hosts() {
    find "${AEGIS_SYSTEM}/src/hosts" -maxdepth 1 -name "*.toml" 2>/dev/null \
        | sed 's|.*/||; s|\.toml$||' \
        | sort || true
}

aegis_roles() {
    find "${AEGIS_SYSTEM}/src/roles" -maxdepth 1 -name "*.toml" 2>/dev/null \
        | sed 's|.*/||; s|\.toml$||' \
        | sort || true
}

aegis_realms() {
    find "${AEGIS_SYSTEM}/src/kerberos/realms" -maxdepth 1 -type d 2>/dev/null \
        | sed 's|.*/||' \
        | grep -v '^realms$' \
        | sort || true
}

# ---------------------------------------------------------------------------
# Initialization functions
# ---------------------------------------------------------------------------

init_realms() {
    info "Checking Kerberos realms..."
    local all_aegis_realms
    all_aegis_realms=$(aegis_realms)
    
    local -a new_realms=()
    while IFS= read -r realm; do
        [[ -z "$realm" ]] && continue
        if ! grep -qx "$realm" <<< "$all_aegis_realms"; then
            new_realms+=("$realm")
        fi
    done < <(jq -r '.realms[]' "$AEGIS_ENTITIES_JSON")

    if [[ ${#new_realms[@]} -gt 0 ]]; then
        for realm in "${new_realms[@]}"; do
            info "  → Initializing realm: $realm"
            aegis init-realm "$realm"
        done
        success "  ✓ Initialized ${#new_realms[@]} realm(s)"
    else
        success "  ✓ All realms already initialized"
    fi
    echo ""
}

init_hosts() {
    info "Checking hosts..."
    local all_aegis_hosts
    all_aegis_hosts=$(aegis_hosts)
    
    local -a new_hosts=()
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        if ! grep -qx "$host" <<< "$all_aegis_hosts"; then
            new_hosts+=("$host")
        fi
    done < <(jq -r '.hosts | keys[]' "$AEGIS_ENTITIES_JSON")

    if [[ ${#new_hosts[@]} -gt 0 ]]; then
        for host in "${new_hosts[@]}"; do
            local domain site realm
            domain=$(jq -r ".hosts.\"$host\".domain // \"\"" "$AEGIS_ENTITIES_JSON")
            site=$(jq -r ".hosts.\"$host\".site // \"\"" "$AEGIS_ENTITIES_JSON")
            realm=$(jq -r ".hosts.\"$host\".realm // \"\"" "$AEGIS_ENTITIES_JSON")
            
            info "  → Initializing host: $host (domain=$domain, site=$site, realm=$realm)"
            
            if [[ -n "$domain" ]]; then
                aegis init-host --domain "$domain" --services "host,ssh" "$host"
            else
                aegis init-host --services "host,ssh" "$host"
            fi
        done
        success "  ✓ Initialized ${#new_hosts[@]} host(s)"
    else
        success "  ✓ All hosts already initialized"
    fi
    echo ""
}

init_domain_roles() {
    info "Checking domain roles..."
    local all_aegis_roles
    all_aegis_roles=$(aegis_roles)
    
    local -a new_roles=()
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        local role="domain-${domain}"
        if ! grep -qx "$role" <<< "$all_aegis_roles"; then
            new_roles+=("$role")
        fi
    done < <(jq -r '.domains | keys[]' "$AEGIS_ENTITIES_JSON")

    if [[ ${#new_roles[@]} -gt 0 ]]; then
        for role in "${new_roles[@]}"; do
            info "  → Initializing role: $role"
            aegis init-role "$role"
        done
        success "  ✓ Initialized ${#new_roles[@]} domain role(s)"
    else
        success "  ✓ All domain roles already initialized"
    fi
    echo ""
}

init_site_roles() {
    info "Checking site roles..."
    local all_aegis_roles
    all_aegis_roles=$(aegis_roles)
    
    local -a new_roles=()
    while IFS= read -r site; do
        [[ -z "$site" ]] && continue
        local role="site-${site}"
        if ! grep -qx "$role" <<< "$all_aegis_roles"; then
            new_roles+=("$role")
        fi
    done < <(jq -r '.sites[]' "$AEGIS_ENTITIES_JSON")

    if [[ ${#new_roles[@]} -gt 0 ]]; then
        for role in "${new_roles[@]}"; do
            info "  → Initializing role: $role"
            aegis init-role "$role"
        done
        success "  ✓ Initialized ${#new_roles[@]} site role(s)"
    else
        success "  ✓ All site roles already initialized"
    fi
    echo ""
}

add_hosts_to_domain_roles() {
    info "Adding hosts to domain roles..."
    local count=0
    
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        local domain site
        domain=$(jq -r ".hosts.\"$host\".domain // \"\"" "$AEGIS_ENTITIES_JSON")
        [[ -z "$domain" ]] && continue
        
        local role="domain-${domain}"
        local role_key="${AEGIS_SYSTEM}/build/hosts/${host}/roles/${role}.age"
        
        if [[ ! -f "$role_key" ]]; then
            info "  → Adding $host to $role"
            aegis add-host-to-role "$role" "$host"
            ((count++))
        fi
    done < <(jq -r '.hosts | keys[]' "$AEGIS_ENTITIES_JSON")

    if [[ $count -gt 0 ]]; then
        success "  ✓ Added $count host(s) to domain roles"
    else
        success "  ✓ All hosts already in their domain roles"
    fi
    echo ""
}

add_hosts_to_site_roles() {
    info "Adding hosts to site roles..."
    local count=0
    
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        local site
        site=$(jq -r ".hosts.\"$host\".site // \"\"" "$AEGIS_ENTITIES_JSON")
        [[ -z "$site" ]] && continue
        
        local role="site-${site}"
        local role_key="${AEGIS_SYSTEM}/build/hosts/${host}/roles/${role}.age"
        
        if [[ ! -f "$role_key" ]]; then
            info "  → Adding $host to $role"
            aegis add-host-to-role "$role" "$host"
            ((count++))
        fi
    done < <(jq -r '.hosts | keys[]' "$AEGIS_ENTITIES_JSON")

    if [[ $count -gt 0 ]]; then
        success "  ✓ Added $count host(s) to site roles"
    else
        success "  ✓ All hosts already in their site roles"
    fi
    echo ""
}

sync_master_keys() {
    info "Syncing Aegis master keys from nix-entities..."
    local count=0
    local skipped=0
    local -a missing_keys
    missing_keys=()
    
    local all_aegis_hosts
    all_aegis_hosts=$(aegis_hosts)
    
    jq -r '.hosts | keys[]' "$AEGIS_ENTITIES_JSON" 2>/dev/null | while read -r host; do
        [[ -z "$host" ]] && continue
        
        # Only sync keys for hosts that exist in aegis
        if ! grep -qx "$host" <<< "$all_aegis_hosts"; then
            continue
        fi
        
        local master_key
        master_key=$(jq -r ".hosts.\"$host\".\"master-key\" // \"\"" "$AEGIS_ENTITIES_JSON")
        
        # Skip if no key, null, or a path (not an age public key)
        if [[ -z "$master_key" || "$master_key" == "null" || "$master_key" =~ ^/ ]]; then
            missing_keys+=("$host")
            ((skipped++))
            continue
        fi
        
        # Validate it's an age public key
        if [[ ! "$master_key" =~ ^age1 ]]; then
            missing_keys+=("$host")
            ((skipped++))
            continue
        fi
        
        # Read current key from host toml
        local current_key
        current_key=$(grep "^age_pubkey" "${AEGIS_SYSTEM}/src/hosts/${host}.toml" 2>/dev/null | cut -d'"' -f2 || echo "")
        
        if [[ "$current_key" != "$master_key" ]]; then
            info "  → Updating master key for $host"
            if aegis set-master-key "$host" --public-key "$master_key" 2>&1; then
                ((count++))
            else
                warn "  ⚠ Failed to update master key for $host"
            fi
        fi
    done

    if [[ $count -gt 0 ]]; then
        success "  ✓ Updated $count master key(s)"
    else
        success "  ✓ All master keys are up to date"
    fi
    
    if [[ $skipped -gt 0 ]]; then
        warn "  ⚠ $skipped host(s) have no valid master-key in nix-entities: ${missing_keys[*]}"
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║                  Fudo Secrets Sync                           ║${NC}"
    echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Validate environment
    if [[ ! -f "$AEGIS_ENTITIES_JSON" ]]; then
        error "AEGIS_ENTITIES_JSON not found: $AEGIS_ENTITIES_JSON"
        error "This should be set automatically in the dev shell."
        exit 1
    fi

    local total_hosts
    total_hosts=$(jq -r '.hosts | keys | length' "$AEGIS_ENTITIES_JSON")
    info "Found $total_hosts hosts in nix-entities"
    echo ""

    # Initialize everything in order
    init_realms
    init_hosts
    sync_master_keys
    init_domain_roles
    init_site_roles
    add_hosts_to_domain_roles
    add_hosts_to_site_roles

    # Build all secrets
    echo -e "${BOLD}Building secrets for all hosts…${NC}"
    echo ""
    aegis build
    echo ""
    echo -e "${GREEN}${BOLD}✓ Sync complete!${NC}"
    echo ""
}

main "$@"

#!/usr/bin/env python3
"""
Fudo Secrets Sync - Synchronize fudo-entities with aegis-secrets.

This script initializes all hosts, roles, and builds secrets by:
1. Initializing missing Kerberos realms
2. Initializing domain, site and DNS master roles
3. Initializing missing hosts with proper domain/realm settings
4. Syncing master keys from nix-entities
5. Adding hosts to their respective roles
6. Building all secrets

Entities come from the fudo-entities flake input, via the AEGIS_ENTITIES_JSON
file the dev shell generates; run this from 'nix develop', not directly.
"""

import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Set


# Colors for output
class Color:
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    GREEN = '\033[0;32m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'


def warn(msg: str) -> None:
    """Print warning message."""
    print(f"{Color.YELLOW}{msg}{Color.NC}", file=sys.stderr)


def error(msg: str) -> None:
    """Print error message."""
    print(f"{Color.RED}{Color.BOLD}{msg}{Color.NC}", file=sys.stderr)


def info(msg: str) -> None:
    """Print info message."""
    print(f"{Color.CYAN}{msg}{Color.NC}")


def success(msg: str) -> None:
    """Print success message."""
    print(f"{Color.GREEN}{msg}{Color.NC}")


def run_command(cmd: List[str], check: bool = True, capture: bool = False) -> Optional[str]:
    """Run a command and optionally capture output."""
    try:
        if capture:
            result = subprocess.run(cmd, check=check, capture_output=True, text=True)
            return result.stdout.strip()
        else:
            subprocess.run(cmd, check=check)
            return None
    except subprocess.CalledProcessError as e:
        if check:
            raise
        return None


class SecretsSync:
    def __init__(self):
        self.aegis_system = os.getenv('AEGIS_SYSTEM', os.getcwd())
        self.entities_json_path = os.getenv('AEGIS_ENTITIES_JSON')
        self.hosts_without_keys = []
        
        if not self.entities_json_path:
            error("AEGIS_ENTITIES_JSON is not set — run this inside the dev shell")
            sys.exit(1)
        
        if not os.path.exists(self.entities_json_path):
            error(f"AEGIS_ENTITIES_JSON not found: {self.entities_json_path}")
            error("This should be set automatically in the dev shell.")
            sys.exit(1)
        
        # Load entities data
        with open(self.entities_json_path) as f:
            self.entities = json.load(f)
    
    def get_aegis_hosts(self) -> Set[str]:
        """Get list of hosts already initialized in aegis."""
        hosts_dir = Path(self.aegis_system) / "src" / "hosts"
        if not hosts_dir.exists():
            return set()
        return {f.stem for f in hosts_dir.glob("*.toml")}
    
    def get_aegis_roles(self) -> Set[str]:
        """Get list of roles already initialized in aegis."""
        roles_dir = Path(self.aegis_system) / "src" / "roles"
        if not roles_dir.exists():
            return set()
        return {f.stem for f in roles_dir.glob("*.toml")}
    
    def get_role_members(self, role: str) -> Set[str]:
        """Hosts already recorded as members of a role, per src/roles/."""
        role_toml = Path(self.aegis_system) / "src" / "roles" / f"{role}.toml"
        if not role_toml.exists():
            return set()
        with open(role_toml, 'rb') as f:
            return set(tomllib.load(f).get('hosts', []))

    def get_nebula_networks(self) -> List[str]:
        """Nebula networks that exist in this repo.

        Empty until someone runs 'aegis nebula init', which is deliberate:
        minting a CA is a one-time act with no undo, so it is not something a
        sync script should do on anyone's behalf.
        """
        networks_dir = Path(self.aegis_system) / "src" / "nebula" / "networks"
        if not networks_dir.exists():
            return []
        return sorted(d.name for d in networks_dir.iterdir() if d.is_dir())

    def get_nebula_members(self, network: str) -> Set[str]:
        """Hosts already on a Nebula network, per src/nebula/networks/<n>/hosts/."""
        hosts_dir = (Path(self.aegis_system) / "src" / "nebula" / "networks"
                     / network / "hosts")
        if not hosts_dir.exists():
            return set()
        return {f.stem for f in hosts_dir.glob("*.toml")}

    def nebula_membership(self, network: str) -> Dict[str, Dict]:
        """Hosts on a Nebula network, as resolved by the entities derivation.

        Membership needs two things to agree: the host names the network in
        `nebula-network`, and the network's zone gives it an address. The
        derivation resolves the address, so a null one here means the host
        named a network but was never given one -- which is not membership.
        """
        out = {}
        nebula_hosts = self.entities.get('nebula', {}).get('hosts', {})
        for hostname, deets in nebula_hosts.items():
            if deets.get('network') != network:
                continue
            if not deets.get('address'):
                continue
            out[hostname] = {
                'address': deets['address'],
                'lighthouse': bool(deets.get('lighthouse')),
                'local_key': bool(deets.get('local-key')),
                'extra_groups': list(deets.get('groups') or []),
                'site': deets.get('site') or '',
                'domain': deets.get('domain') or '',
                'profile': deets.get('profile') or [],
                'public_ipv4': deets.get('endpoint-ipv4'),
            }
        return out

    def add_hosts_to_nebula(self) -> None:
        """Put the entity-declared hosts on each Nebula network.

        Only hosts not already on the network, which is what makes re-running
        safe. That does mean a flag changed in the entity data after a host was
        added does not follow -- so disagreements are reported rather than
        silently ignored.

        A network with members but no CA is reported too, never created:
        minting a CA decides who can forge membership on that mesh forever, and
        that is not a decision a sync run should make on anyone's behalf.
        """
        networks = self.get_nebula_networks()
        declared = self.entities.get('nebula', {}).get('networks', {})

        for network in sorted(declared):
            if network not in networks:
                members = self.nebula_membership(network)
                warn(f"Nebula network '{network}' has {len(members)} host(s) "
                     f"in the entity data but no CA in this repo.")
                cidr = declared[network].get('cidr', '<cidr>')
                warn(f"  Create it with: aegis nebula init {network} "
                     f"--cidr {cidr}")
                print()

        if not networks:
            return

        for network in networks:
            info(f"Adding hosts to Nebula network '{network}'...")
            existing = self.get_nebula_members(network)
            members = self.nebula_membership(network)
            count = 0

            for hostname, deets in sorted(members.items()):
                if hostname in existing:
                    self.check_nebula_drift(network, hostname, deets)
                    continue

                # Certificate groups are what Nebula firewall rules match on.
                # Naming them after the roles this repo already uses keeps one
                # vocabulary across both: a rule reading 'site-seattle' means
                # the same thing as the role of that name.
                groups = []
                if deets['site']:
                    groups.append(f"site-{deets['site']}")
                if deets['domain']:
                    groups.append(f"domain-{deets['domain']}")
                profile = deets['profile']
                groups.extend(profile if isinstance(profile, list) else [profile])
                groups.extend(deets['extra_groups'])

                cmd = ['aegis', 'nebula', 'add-host', '--network', network,
                       '--address', deets['address']]
                if groups:
                    cmd.extend(['--groups', ','.join(g for g in groups if g)])
                if deets['local_key']:
                    cmd.append('--local-key')
                if deets['lighthouse']:
                    cmd.append('--lighthouse')
                    endpoint_host = deets['public_ipv4']
                    if endpoint_host:
                        port = declared.get(network, {}).get('port', 4242)
                        cmd.extend(['--endpoint', f"{endpoint_host}:{port}"])
                    else:
                        warn(f"  ⚠ {hostname} is a lighthouse but has no address "
                             f"in its own domain's zone; nobody can reach it")
                cmd.append(hostname)

                info(f"  → Adding {hostname} to {network} at {deets['address']}")
                try:
                    run_command(cmd)
                    count += 1
                except subprocess.CalledProcessError:
                    error(f"  ✗ Failed to add {hostname} to {network}")

            # A host removed from the entity data keeps its certificate until
            # someone says otherwise: dropping it is a revocation, and this
            # script does not revoke.
            orphans = existing - set(members)
            if orphans:
                warn(f"  ⚠ on {network} but no longer in the entity data: "
                     f"{' '.join(sorted(orphans))}")
                warn(f"     They keep their certificates. To remove one, "
                     f"blocklist it and delete its host file.")

            if count > 0:
                success(f"  ✓ Added {count} host(s) to {network}")
            else:
                success(f"  ✓ All hosts already on {network}")

    def check_nebula_drift(self, network: str, hostname: str,
                           deets: Dict) -> None:
        """Report entity data that disagrees with what Aegis already has.

        Hosts are only ever added, never rewritten, so a flag flipped in the
        entity data after the fact would otherwise take effect nowhere and say
        nothing.
        """
        host_toml = (Path(self.aegis_system) / "src" / "nebula" / "networks"
                     / network / "hosts" / f"{hostname}.toml")
        if not host_toml.exists():
            return
        with open(host_toml, 'rb') as f:
            current = tomllib.load(f)

        for field, want, have in (
            ('address', deets['address'], current.get('address')),
            ('lighthouse', deets['lighthouse'],
             bool(current.get('lighthouse', False))),
            ('local_key', deets['local_key'],
             bool(current.get('local_key', False))),
        ):
            if want != have:
                warn(f"  ⚠ {hostname}: entities say {field}={want}, "
                     f"aegis has {have}")
                if field == 'address':
                    warn(f"     Edit {host_toml} and re-sign: the address is "
                         f"baked into the certificate.")
                else:
                    warn(f"     Edit {host_toml} to change it.")

    def get_aegis_realms(self) -> Set[str]:
        """Get list of Kerberos realms already initialized."""
        realms_dir = Path(self.aegis_system) / "src" / "kerberos" / "realms"
        if not realms_dir.exists():
            return set()
        return {d.name for d in realms_dir.iterdir() if d.is_dir()}
    
    def init_realms(self) -> None:
        """Initialize missing Kerberos realms."""
        info("Checking Kerberos realms...")
        existing_realms = self.get_aegis_realms()
        new_realms = [r for r in self.entities.get('realms', []) if r not in existing_realms]
        
        if new_realms:
            for realm in new_realms:
                info(f"  → Initializing realm: {realm}")
                try:
                    run_command(['aegis', 'realm', 'init', realm])
                except subprocess.CalledProcessError:
                    error(f"  ✗ Failed to initialize realm: {realm}")
            success(f"  ✓ Initialized {len(new_realms)} realm(s)")
        else:
            success("  ✓ All realms already initialized")
        print()
    
    def init_hosts(self) -> None:
        """Initialize missing hosts."""
        info("Checking hosts...")
        existing_hosts = self.get_aegis_hosts()
        hosts_data = self.entities.get('hosts', {})
        new_hosts = [h for h in hosts_data.keys() if h not in existing_hosts]
        
        if new_hosts:
            for hostname in new_hosts:
                host_info = hosts_data[hostname]
                domain = host_info.get('domain', '')
                site = host_info.get('site', '')
                realm = host_info.get('realm', '')
                
                info(f"  → Initializing host: {hostname} (domain={domain}, site={site}, realm={realm})")
                
                cmd = ['aegis', 'host', 'add', '--services', 'host,ssh']
                if domain:
                    cmd.extend(['--domain', domain])
                cmd.append(hostname)
                
                try:
                    run_command(cmd)
                except subprocess.CalledProcessError:
                    error(f"  ✗ Failed to initialize host: {hostname}")
            
            success(f"  ✓ Initialized {len(new_hosts)} host(s)")
        else:
            success("  ✓ All hosts already initialized")
        print()
    
    def sync_master_keys(self) -> None:
        """Sync Aegis master keys from nix-entities."""
        info("Syncing Aegis master keys from nix-entities...")
        
        existing_hosts = self.get_aegis_hosts()
        hosts_data = self.entities.get('hosts', {})
        
        updated = 0
        skipped = 0
        missing_keys = []
        
        for hostname, host_info in hosts_data.items():
            # Only sync keys for hosts that exist in aegis
            if hostname not in existing_hosts:
                continue
            
            master_key = host_info.get('master-key')
            
            # Skip if no key, null, or a path (not an age public key)
            if not master_key or master_key.startswith('/'):
                missing_keys.append(hostname)
                skipped += 1
                continue
            
            # Validate it's an age public key
            if not re.match(r'^age1', master_key):
                missing_keys.append(hostname)
                skipped += 1
                continue
            
            # Read current key from host toml
            host_toml = Path(self.aegis_system) / "src" / "hosts" / f"{hostname}.toml"
            current_key = None
            if host_toml.exists():
                with open(host_toml, 'rb') as f:
                    current_key = tomllib.load(f).get('age_pubkey')

            if current_key != master_key:
                info(f"  → Updating master key for {hostname}")
                try:
                    run_command(['aegis', 'host', 'set-key', hostname, '--public-key', master_key])
                    updated += 1
                except subprocess.CalledProcessError:
                    warn(f"  ⚠ Failed to update master key for {hostname}")
        
        if updated > 0:
            success(f"  ✓ Updated {updated} master key(s)")
        else:
            success("  ✓ All master keys are up to date")
        
        if skipped > 0:
            warn(f"  ⚠ {skipped} host(s) have no valid master-key: {' '.join(missing_keys)}")
            warn(f"     These hosts will be skipped during build")
        
        # Return the list of missing keys so we can warn before build
        self.hosts_without_keys = missing_keys
        print()
    
    def init_domain_roles(self) -> None:
        """Initialize domain roles."""
        info("Checking domain roles...")
        existing_roles = self.get_aegis_roles()
        domains = self.entities.get('domains', {}).keys()
        new_roles = [f"domain-{domain}" for domain in domains if f"domain-{domain}" not in existing_roles]
        
        if new_roles:
            for role in new_roles:
                info(f"  → Initializing role: {role}")
                try:
                    run_command(['aegis', 'role', 'init', role])
                except subprocess.CalledProcessError:
                    error(f"  ✗ Failed to initialize role: {role}")
            success(f"  ✓ Initialized {len(new_roles)} domain role(s)")
        else:
            success("  ✓ All domain roles already initialized")
        print()
    
    def init_site_roles(self) -> None:
        """Initialize site roles."""
        info("Checking site roles...")
        existing_roles = self.get_aegis_roles()
        sites = self.entities.get('sites', [])
        new_roles = [f"site-{site}" for site in sites if f"site-{site}" not in existing_roles]
        
        if new_roles:
            for role in new_roles:
                info(f"  → Initializing role: {role}")
                try:
                    run_command(['aegis', 'role', 'init', role])
                except subprocess.CalledProcessError:
                    error(f"  ✗ Failed to initialize role: {role}")
            success(f"  ✓ Initialized {len(new_roles)} site role(s)")
        else:
            success("  ✓ All site roles already initialized")
        print()
    
    def init_dns_master_roles(self) -> None:
        """Initialize DNS master roles for each domain/zone."""
        info("Checking DNS master roles...")
        existing_roles = self.get_aegis_roles()
        domains = self.entities.get('domains', {}).keys()
        new_roles = [f"dns-master-{domain}" for domain in domains if f"dns-master-{domain}" not in existing_roles]
        
        if new_roles:
            for role in new_roles:
                info(f"  → Initializing role: {role}")
                try:
                    run_command(['aegis', 'role', 'init', role])
                except subprocess.CalledProcessError:
                    error(f"  ✗ Failed to initialize role: {role}")
            success(f"  ✓ Initialized {len(new_roles)} DNS master role(s)")
        else:
            success("  ✓ All DNS master roles already initialized")
        print()
    
    def add_hosts_to_roles(self, kind: str, entity_key: str, prefix: str) -> None:
        """Add hosts to the roles derived from one of their entity fields.

        Membership is read from src/roles/<role>.toml, which is where aegis
        records it, and NOT from the per-host role key file. Two reasons:

        - 'aegis host add --domain X' now records domain membership itself,
          without writing a key. Keying off the key file would then re-run
          'aegis role add-host', which exits 1 for a host that is already a
          member -- reporting a failure for something that is already right.
        - A member missing its key is not this script's problem to fix:
          'aegis build' runs 'build role-keys', which writes a key for every
          member that lacks one. That runs at the end of this sync.
        """
        info(f"Adding hosts to {kind} roles...")

        count = 0
        hosts_data = self.entities.get('hosts', {})

        for hostname, host_info in hosts_data.items():
            value = host_info.get(entity_key)
            if not value:
                continue

            role = f"{prefix}{value}"
            if hostname in self.get_role_members(role):
                continue

            info(f"  → Adding {hostname} to {role}")
            try:
                run_command(['aegis', 'role', 'add-host', role, hostname])
                count += 1
            except subprocess.CalledProcessError:
                error(f"  ✗ Failed to add {hostname} to {role}")

        if count > 0:
            success(f"  ✓ Added {count} host(s) to {kind} roles")
        else:
            success(f"  ✓ All hosts already in their {kind} roles")
        print()

    def build_secrets(self) -> None:
        """Build all secrets."""
        print(f"{Color.BOLD}Building secrets for all hosts…{Color.NC}")
        print()
        
        if self.hosts_without_keys:
            warn(f"Note: {len(self.hosts_without_keys)} host(s) without master keys may fail to build")
            warn(f"      Hosts: {' '.join(self.hosts_without_keys)}")
            print()
        
        try:
            run_command(['aegis', 'build'])
        except subprocess.CalledProcessError as e:
            print()
            # If there are hosts without keys, this is expected - treat as warning
            if self.hosts_without_keys:
                warn("Build completed with warnings.")
                warn(f"Hosts without master keys could not be built: {' '.join(self.hosts_without_keys)}")
                warn("Set master keys with: aegis host set-key <host> --public-key 'age1...'")
                print()
                return  # Continue successfully despite build errors
            else:
                # Unexpected build failure
                error("Build failed unexpectedly.")
                sys.exit(e.returncode)
        print()
    
    def run(self) -> None:
        """Main entry point."""
        print()
        print(f"{Color.BOLD}╔═══════════════════════════════════════════════════════════════╗{Color.NC}")
        print(f"{Color.BOLD}║                  Fudo Secrets Sync                           ║{Color.NC}")
        print(f"{Color.BOLD}╚═══════════════════════════════════════════════════════════════╝{Color.NC}")
        print()
        
        total_hosts = len(self.entities.get('hosts', {}))
        info(f"Found {total_hosts} hosts in nix-entities")
        print()
        
        # Roles are created before hosts on purpose: 'aegis host add --domain X'
        # records membership in domain-X, but only if that role already exists.
        # Creating hosts first means every new host prints "role does not exist
        # yet" and has to be added again below.
        self.init_realms()
        self.init_domain_roles()
        self.init_site_roles()
        self.init_dns_master_roles()
        self.init_hosts()
        self.sync_master_keys()
        self.add_hosts_to_roles("domain", "domain", "domain-")
        self.add_hosts_to_roles("site", "site", "site-")
        self.add_hosts_to_nebula()

        # Build all secrets. This also writes a role key for every member that
        # does not have one yet, and reconciles role secrets into the manifests
        # of hosts that just joined a role.
        self.build_secrets()
        
        print(f"{Color.GREEN}{Color.BOLD}✓ Sync complete!{Color.NC}")
        print()


if __name__ == '__main__':
    try:
        sync = SecretsSync()
        sync.run()
    except KeyboardInterrupt:
        print()
        error("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        error(f"Unexpected error: {e}")
        # Uncomment for debugging:
        # import traceback
        # traceback.print_exc()
        sys.exit(1)

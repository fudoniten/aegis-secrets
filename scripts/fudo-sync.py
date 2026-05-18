#!/usr/bin/env python3
"""
Fudo Secrets Sync - Synchronize fudo-nix-entities with aegis-secrets.

This script initializes all hosts, roles, and builds secrets by:
1. Initializing missing Kerberos realms
2. Initializing missing hosts with proper domain/realm settings
3. Syncing master keys from nix-entities
4. Initializing domain and site roles
5. Adding hosts to their respective roles
6. Building all secrets
"""

import json
import os
import re
import subprocess
import sys
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
                    run_command(['aegis', 'init-realm', realm])
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
                
                cmd = ['aegis', 'init-host', '--services', 'host,ssh']
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
                with open(host_toml) as f:
                    for line in f:
                        if line.startswith('age_pubkey'):
                            current_key = line.split('"')[1] if '"' in line else None
                            break
            
            if current_key != master_key:
                info(f"  → Updating master key for {hostname}")
                try:
                    run_command(['aegis', 'set-master-key', hostname, '--public-key', master_key])
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
                    run_command(['aegis', 'init-role', role])
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
                    run_command(['aegis', 'init-role', role])
                except subprocess.CalledProcessError:
                    error(f"  ✗ Failed to initialize role: {role}")
            success(f"  ✓ Initialized {len(new_roles)} site role(s)")
        else:
            success("  ✓ All site roles already initialized")
        print()
    
    def add_hosts_to_domain_roles(self) -> None:
        """Add hosts to their domain roles."""
        info("Adding hosts to domain roles...")
        
        count = 0
        hosts_data = self.entities.get('hosts', {})
        
        for hostname, host_info in hosts_data.items():
            domain = host_info.get('domain')
            if not domain:
                continue
            
            role = f"domain-{domain}"
            role_key = Path(self.aegis_system) / "build" / "hosts" / hostname / "roles" / f"{role}.age"
            
            if not role_key.exists():
                info(f"  → Adding {hostname} to {role}")
                try:
                    run_command(['aegis', 'add-host-to-role', role, hostname])
                    count += 1
                except subprocess.CalledProcessError:
                    error(f"  ✗ Failed to add {hostname} to {role}")
        
        if count > 0:
            success(f"  ✓ Added {count} host(s) to domain roles")
        else:
            success("  ✓ All hosts already in their domain roles")
        print()
    
    def add_hosts_to_site_roles(self) -> None:
        """Add hosts to their site roles."""
        info("Adding hosts to site roles...")
        
        count = 0
        hosts_data = self.entities.get('hosts', {})
        
        for hostname, host_info in hosts_data.items():
            site = host_info.get('site')
            if not site:
                continue
            
            role = f"site-{site}"
            role_key = Path(self.aegis_system) / "build" / "hosts" / hostname / "roles" / f"{role}.age"
            
            if not role_key.exists():
                info(f"  → Adding {hostname} to {role}")
                try:
                    run_command(['aegis', 'add-host-to-role', role, hostname])
                    count += 1
                except subprocess.CalledProcessError:
                    error(f"  ✗ Failed to add {hostname} to {role}")
        
        if count > 0:
            success(f"  ✓ Added {count} host(s) to site roles")
        else:
            success("  ✓ All hosts already in their site roles")
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
                warn("Set master keys with: aegis set-master-key <host> --public-key 'age1...'")
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
        
        # Initialize everything in order
        self.init_realms()
        self.init_hosts()
        self.sync_master_keys()
        self.init_domain_roles()
        self.init_site_roles()
        self.add_hosts_to_domain_roles()
        self.add_hosts_to_site_roles()
        
        # Build all secrets
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

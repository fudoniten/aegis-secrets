#!/usr/bin/env python3
"""
Fudo Secrets Sync - Synchronize fudo-entities with aegis-secrets.

This script initializes all hosts, roles, and builds secrets by:
1. Initializing missing Kerberos realms
2. Initializing domain, site and DNS master roles
3. Initializing missing hosts with proper domain/realm settings
4. Syncing master keys from nix-entities
5. Migrating Nexus keys to the ed25519 (/api/v3) format
6. Adding hosts to their respective roles
7. Ensuring sea/burg hosts declare an 'nfs' Kerberos service
8. Generating and importing wallfly presence passwords
9. Generating and importing domain MQTT service passwords
10. Building all secrets

Entities come from the fudo-entities flake input, via the AEGIS_ENTITIES_JSON
file the dev shell generates; run this from 'nix develop', not directly.
"""

import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Set


#: Sites where fudo.services.wallfly-presence is enabled
#: (nixos-config site/<site>/global.nix). That's a NixOS module option, not
#: entity data, so -- like LOCAL_NETWORK_DOMAINS below -- it's hardcoded
#: here and has to be kept in sync by hand.
WALLFLY_SITES = {"seattle"}

#: Each site's MQTT broker host, i.e. its config.fudo.services.mqtt.host
#: (domain/<domain>/config.nix). Also not entity data. Shared by wallfly's
#: broker-side secrets and MQTT_SERVICES below -- every broker-side MQTT
#: secret for a site goes to the same host, via the same role
#: (see MQTT_BROKER_ROLE / _ensure_role).
MQTT_BROKER_HOSTS = {"seattle": "wormhole0"}

#: Domain-level services whose MQTT broker-side password this script
#: manages, keyed by site. Client-side secrets, where a service needs one
#: at all, are listed separately below (MQTT_CLIENT_SECRETS) -- most of
#: these either have no client-side reference to migrate (their own MQTT
#: credential is configured out of band) or read it as a raw string baked
#: into the Nix store at eval time, which isn't migratable without an
#: upstream module change.
MQTT_SERVICES = {
    "seattle": [
        "frigate", "home-assistant", "node-red", "teslamate", "zigbee2mqtt"
    ],
}

#: Per-service client-side secret, for the few MQTT services whose own
#: config reads the password from a file at runtime (nixos-config
#: password-file) rather than out of band or as a baked-in string. Keyed
#: by service name; value is (host, unix user, target path).
MQTT_CLIENT_SECRETS = {
    "frigate": ("zbox", "frigate", "/run/mqtt-client/frigate.passwd"),
}


def mqtt_broker_role(site: str) -> str:
    return f"mqtt-broker-{site}"

#: Domains whose hosts sit on a local network and so are expected to use NFS.
#: 'sea.fudo.org' uses it today; 'burg.fudo.org' doesn't yet, but there's no
#: harm in every host there having the principal ready before it does.
LOCAL_NETWORK_DOMAINS = {"sea.fudo.org", "burg.fudo.org"}


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

            # Finding nothing is not success. The entity data reaches this
            # script through a derivation in flake.nix and a store path fixed
            # when the dev shell started, so there are several ways for it to
            # arrive empty -- and reporting "all hosts already added" for an
            # empty set sends you looking in entirely the wrong place.
            if not members:
                warn(f"  ⚠ No host declares network '{network}' in the entity "
                     f"data, so there is nothing to add.")
                warn(f"     Check what this script can actually see:")
                warn(f"       jq '.nebula.networks' \"$AEGIS_ENTITIES_JSON\"")
                warn(f"       jq '.nebula.hosts | length' \"$AEGIS_ENTITIES_JSON\"")
                warn(f"     null means this repo's flake.nix predates the "
                     f"Nebula export, or the dev shell is older than it -- "
                     f"leave and re-enter 'nix develop'.")
                warn(f"     Empty means the fudo-entities input predates the "
                     f"network: 'nix flake update fudo-entities'.")
                continue

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

                services = ['host', 'ssh']
                if domain in LOCAL_NETWORK_DOMAINS:
                    services.append('nfs')
                cmd = ['aegis', 'host', 'add', '--services', ','.join(services)]
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

    def add_service_to_host_toml(self, hostname: str, service: str) -> bool:
        """Add a Kerberos service to an already-onboarded host's declared
        services, by editing src/hosts/<host>.toml directly.

        There's no 'aegis host' subcommand for this today -- 'aegis host add'
        only covers a brand-new host, and set-key/set-status/set-placement
        don't touch 'services'. So this does the minimal, format-preserving
        edit: insert one quoted string into the existing 'services' array,
        leaving everything else in the file untouched.

        Declaring the service here is the whole fix. It doesn't create the
        principal itself: 'aegis build' does that as part of extracting each
        host's keytab (cli.py's build-keytabs step adds any service present
        in 'services' but not yet in the realm, the same way 'host' and
        'ssh' already land there) -- which is also what ties the resulting
        principal to this host, rather than leaving it a standalone
        principal nothing carries.

        Returns True if the file was changed, False if the service was
        already declared.
        """
        host_toml = Path(self.aegis_system) / "src" / "hosts" / f"{hostname}.toml"
        if not host_toml.exists():
            warn(f"  ⚠ {hostname}: no {host_toml}, skipping")
            return False

        text = host_toml.read_text()
        match = re.search(r"services\s*=\s*\[(.*?)\]", text, re.DOTALL)
        if not match:
            warn(f"  ⚠ {hostname}: no 'services' array found in {host_toml}, skipping")
            return False

        if service in re.findall(r'"([^"]+)"', match.group(1)):
            return False

        # Match the existing entries' own indentation, so the inserted line
        # reads like the rest of the array rather than a machine patch. Falls
        # back to a plain comma-separated insertion for a single-line array,
        # which nothing in this repo currently uses but which 'services =
        # ["host", "ssh"]' would otherwise silently corrupt.
        indent_match = re.search(r'\n(\s*)"', match.group(1))
        if indent_match:
            addition = f'{indent_match.group(1)}"{service}",\n'
            insert_at = match.end(1)
        else:
            addition = f', "{service}"'
            insert_at = match.end(1)

        host_toml.write_text(text[:insert_at] + addition + text[insert_at:])
        return True

    def ensure_local_nfs_principals(self) -> None:
        """Make sure every already-onboarded sea/burg host declares 'nfs'.

        NFS is universal on the local networks, so every host there should
        carry an nfs/<fqdn> principal. Nothing has ever added 'nfs' to a
        host's services list before this -- checked against all 48 existing
        host tomls, including the ~30 sea hosts whose realm.toml already
        carries an nfs/<fqdn> principal left over from importing the old
        /secrets realm dump: none of them declare the service, so none of
        them actually get it in their keytab. Declaring it here is what lets
        the next 'aegis build' create (where missing) and extract it.

        Scoped to hosts already known to aegis and to LOCAL_NETWORK_DOMAINS,
        the same domain field 'init_hosts' reads -- so a host not tracked in
        fudo-entities (an older, hand-added host) is left alone, same as the
        rest of this script only acting on what entities declares.
        """
        info("Ensuring 'nfs' service on sea/burg hosts...")
        existing_hosts = self.get_aegis_hosts()
        hosts_data = self.entities.get('hosts', {})

        changed = []
        for hostname, host_info in sorted(hosts_data.items()):
            if host_info.get('domain') not in LOCAL_NETWORK_DOMAINS:
                continue
            if hostname not in existing_hosts:
                continue
            if self.add_service_to_host_toml(hostname, "nfs"):
                info(f"  → Added 'nfs' to {hostname}")
                changed.append(hostname)

        if changed:
            success(f"  ✓ Added 'nfs' service to {len(changed)} host(s): "
                    f"{' '.join(changed)}")
        else:
            success("  ✓ All sea/burg hosts already declare 'nfs'")
        print()

    def _role_secret_exists(self, role: str, name: str) -> bool:
        return (Path(self.aegis_system) / "deploy" / "roles" / role
                / "secrets" / f"{name}.age").exists()

    def _host_secret_exists(self, host: str, name: str) -> bool:
        return (Path(self.aegis_system) / "deploy" / "hosts" / host
                / "secrets" / f"{name}.age").exists()

    def _ensure_role(self, role: str, members: List[str],
                      existing_roles: Set[str]) -> bool:
        """Create `role` if missing and add any of `members` not already in
        it. Mutates `existing_roles` in place, so callers checking several
        roles in a loop don't re-hit the filesystem for each one.

        Returns whether the role is usable (existed already, or was just
        created) -- False only if 'aegis role init' itself failed.
        """
        if role not in existing_roles:
            info(f"  → Initializing role: {role}")
            try:
                run_command(['aegis', 'role', 'init', role])
                existing_roles.add(role)
            except subprocess.CalledProcessError:
                error(f"  ✗ Failed to initialize role: {role}")
                return False

        current_members = self.get_role_members(role)
        for hostname in members:
            if hostname in current_members:
                continue
            info(f"  → Adding {hostname} to {role}")
            try:
                run_command(['aegis', 'role', 'add-host', role, hostname])
            except subprocess.CalledProcessError:
                error(f"  ✗ Failed to add {hostname} to {role}")
        return True

    def _import_paired_secret(self, description: str, client_args: List[str],
                               broker_args: Optional[List[str]]) -> str:
        """Generate one password and import it under a client-side
        name/placement and, if `broker_args` is given, a broker-side one
        too, both carrying the same value. Returns 'generated' or 'failed'.

        client_args/broker_args are the recipient + placement flags for
        'aegis secret import <name> ...' -- everything after the name and
        before '--file'. Pass broker_args=None for a client-only import
        (e.g. wallfly when the site's broker isn't onboarded yet) --
        there's nothing to keep in sync in that case, so it's a plain
        single import rather than a pairing with nothing to pair against.
        """
        password = secrets.token_urlsafe(32)
        fd, tmp_path = tempfile.mkstemp()
        try:
            os.chmod(tmp_path, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(password)

            info(f"  → Generating {description}")
            try:
                run_command(['aegis', 'secret', 'import', *client_args,
                             '--file', tmp_path])
            except subprocess.CalledProcessError:
                error(f"  ✗ Failed to import client-side {description}")
                return 'failed'

            if broker_args is None:
                return 'generated'

            try:
                run_command(['aegis', 'secret', 'import', *broker_args,
                             '--file', tmp_path])
            except subprocess.CalledProcessError:
                error(f"  ✗ Failed to import broker-side {description} -- "
                      f"the client-side copy is now live with no matching "
                      f"broker copy")
                return 'failed'
            return 'generated'
        finally:
            os.unlink(tmp_path)

    def ensure_wallfly_secrets(self) -> None:
        """Generate and import wallfly passwords for each WALLFLY_SITES site.

        Each user needs two copies of the SAME password, since it's checked
        on two different hosts by two different owners:
        wallfly-<user>-passwd (client side, read by wallfly itself as
        <user>) and mqtt-wallfly-<user>-passwd (broker side, read by
        mosquitto, via the shared mqtt-broker-<site> role -- see
        _ensure_role and mqtt_broker_role). They're generated and imported
        together so the two copies can never independently drift -- this
        script has no way to read a secret back out once encrypted, so if
        only one side existed already there would be no correct value to
        give the other, only a guess. That case is left alone with a
        warning rather than guessed at.

        The client copy goes to a role scoped to the site's NON-hardened
        hosts, deliberately narrower than the pre-existing 'site-<site>'
        role: a hardened host restricts its NixOS local-users to admins
        (nixos-config system/instance.nix), so a role secret naming a
        non-admin owner would fail Aegis's ownership assertion the moment
        that host leaves dry-run -- even though nixos-config's
        services/wallfly-presence.nix would never have looked for the
        secret there in the first place. Hardened hosts keep reading the
        legacy build-seed-derived password for now; giving them Aegis
        coverage too is future work, not a blocker for everyone else.

        Idempotent: a user with both secrets already in place is skipped.
        """
        info("Ensuring wallfly secrets...")

        hosts_data = self.entities.get('hosts', {})
        domains_data = self.entities.get('domains', {})
        sites_data = self.entities.get('sites', {})
        existing_hosts = self.get_aegis_hosts()
        existing_roles = self.get_aegis_roles()

        generated = 0
        already_done = 0
        mismatched = []

        for site in sorted(WALLFLY_SITES):
            broker_host = MQTT_BROKER_HOSTS.get(site)
            if broker_host is None:
                warn(f"  ⚠ {site}: no MQTT_BROKER_HOSTS entry, skipping")
                continue

            site_hosts = {name: info for name, info in hosts_data.items()
                          if info.get('site') == site}
            non_hardened = sorted(
                name for name, info in site_hosts.items()
                if not info.get('hardened', False) and name in existing_hosts)

            if not non_hardened:
                warn(f"  ⚠ {site}: no onboarded non-hardened hosts, skipping")
                continue

            role = f"wallfly-{site}"
            if not self._ensure_role(role, non_hardened, existing_roles):
                warn(f"  ⚠ {site}: skipping, role {role} unavailable")
                continue

            broker_ready = broker_host in existing_hosts
            broker_role = mqtt_broker_role(site)
            if broker_ready:
                broker_ready = self._ensure_role(
                    broker_role, [broker_host], existing_roles)
            if not broker_ready:
                warn(f"  ⚠ {site}: broker host {broker_host} not ready, "
                     f"skipping broker-side secrets")

            # Mirrors services/wallfly-presence.nix's
            # `site-users ++ domain-users`: every domain any host at this
            # site belongs to contributes its local-users, alongside the
            # site's own.
            site_users = set(sites_data.get(site, {}).get('local-users', []))
            site_domains = {info['domain'] for info in site_hosts.values()
                             if info.get('domain')}
            domain_users: Set[str] = set()
            for domain in site_domains:
                domain_users.update(
                    domains_data.get(domain, {}).get('local-users', []))
            wallfly_users = sorted(site_users | domain_users)

            for username in wallfly_users:
                client_name = f"wallfly-{username}-passwd"
                broker_name = f"mqtt-wallfly-{username}-passwd"

                client_done = self._role_secret_exists(role, client_name)
                broker_done = (not broker_ready) or self._role_secret_exists(
                    broker_role, broker_name)

                if client_done and broker_done:
                    already_done += 1
                    continue

                if client_done != broker_done:
                    mismatched.append(f"{username} ({site})")
                    continue

                description = (f"wallfly secrets for {username} ({site})"
                               if broker_ready else
                               f"wallfly secret for {username} "
                               f"({site}, no broker yet)")
                result = self._import_paired_secret(
                    description,
                    client_args=[
                        client_name, '--role', role,
                        '--target', f'/run/wallfly-{username}/passwd',
                        '--user', username, '--mode', '0400'
                    ],
                    broker_args=[
                        broker_name, '--role', broker_role,
                        '--target',
                        f'/run/mqtt/private-wallfly-{username}.passwd',
                        '--user', 'mosquitto', '--group', 'mosquitto'
                    ] if broker_ready else None,
                )
                if result == 'generated':
                    generated += 1

        if generated > 0:
            success(f"  ✓ Generated {generated} wallfly secret(s)")
        if already_done > 0:
            success(f"  ✓ {already_done} wallfly user(s) already fully "
                    f"provisioned")
        if mismatched:
            warn(f"  ⚠ Client/broker secret exists on only one side for: "
                 f"{', '.join(mismatched)}. Not guessing a value for the "
                 f"missing half -- resolve by hand (rotate both together "
                 f"with 'aegis secret import ... --force').")
        if generated == 0 and already_done == 0 and not mismatched:
            success("  ✓ Nothing to do")
        print()

    def ensure_mqtt_service_secrets(self) -> None:
        """Generate and import MQTT broker (and, for the few that need one,
        client) passwords for the domain-level services in MQTT_SERVICES.

        Every broker-side secret for a site's services goes through the
        same mqtt-broker-<site> role wallfly's broker secrets use --
        'Prefer --role for anything that belongs to a *service* rather
        than to a machine' (aegis's own 'secret import --help') applies
        just as well to the broker host itself: if wormhole0 is ever
        replaced, that's a role membership change, not five (or more)
        re-imports.

        Most of these services have no client-side secret to generate at
        all: MQTT_CLIENT_SECRETS lists the ones that do (today, only
        frigate -- see nixos-config's domain/sea.fudo.org/config.nix for
        why the others are either out-of-band or blocked on an upstream
        eval-time-string issue). A service not listed there gets its
        broker-side secret alone, no pairing, no mismatch tracking.
        """
        info("Ensuring MQTT service secrets...")

        existing_hosts = self.get_aegis_hosts()
        existing_roles = self.get_aegis_roles()

        generated = 0
        already_done = 0
        mismatched = []

        for site, services in sorted(MQTT_SERVICES.items()):
            broker_host = MQTT_BROKER_HOSTS.get(site)
            if broker_host is None:
                warn(f"  ⚠ {site}: no MQTT_BROKER_HOSTS entry, skipping")
                continue
            if broker_host not in existing_hosts:
                warn(f"  ⚠ {site}: broker host {broker_host} not yet in "
                     f"aegis, skipping")
                continue

            broker_role = mqtt_broker_role(site)
            if not self._ensure_role(broker_role, [broker_host],
                                      existing_roles):
                warn(f"  ⚠ {site}: skipping, role {broker_role} unavailable")
                continue

            for service in services:
                broker_name = f"mqtt-{service}-passwd"
                broker_done = self._role_secret_exists(
                    broker_role, broker_name)

                client = MQTT_CLIENT_SECRETS.get(service)
                if client is None:
                    if broker_done:
                        already_done += 1
                        continue
                    password = secrets.token_urlsafe(32)
                    fd, tmp_path = tempfile.mkstemp()
                    try:
                        os.chmod(tmp_path, 0o600)
                        with os.fdopen(fd, 'w') as f:
                            f.write(password)
                        info(f"  → Generating {broker_name} ({broker_role})")
                        try:
                            run_command([
                                'aegis', 'secret', 'import', broker_name,
                                '--role', broker_role, '--file', tmp_path,
                                '--target',
                                f'/run/mqtt/private-{service}.passwd',
                                '--user', 'mosquitto', '--group', 'mosquitto'
                            ])
                            generated += 1
                        except subprocess.CalledProcessError:
                            error(f"  ✗ Failed to import {broker_name}")
                    finally:
                        os.unlink(tmp_path)
                    continue

                client_host, client_user, client_target = client
                client_name = f"{service}-mqtt-passwd"

                if client_host not in existing_hosts:
                    warn(f"  ⚠ {service}: client host {client_host} not "
                         f"yet in aegis, skipping")
                    continue

                client_done = self._host_secret_exists(
                    client_host, client_name)

                if client_done and broker_done:
                    already_done += 1
                    continue

                if client_done != broker_done:
                    mismatched.append(f"{service} ({site})")
                    continue

                result = self._import_paired_secret(
                    f"{service} MQTT secrets ({site})",
                    client_args=[
                        client_name, '--host', client_host,
                        '--target', client_target,
                        '--user', client_user, '--mode', '0400'
                    ],
                    broker_args=[
                        broker_name, '--role', broker_role,
                        '--target', f'/run/mqtt/private-{service}.passwd',
                        '--user', 'mosquitto', '--group', 'mosquitto'
                    ],
                )
                if result == 'generated':
                    generated += 1

        if generated > 0:
            success(f"  ✓ Generated {generated} MQTT service secret(s)")
        if already_done > 0:
            success(f"  ✓ {already_done} MQTT service(s) already fully "
                    f"provisioned")
        if mismatched:
            warn(f"  ⚠ Client/broker secret exists on only one side for: "
                 f"{', '.join(mismatched)}. Not guessing a value for the "
                 f"missing half -- resolve by hand (rotate both together "
                 f"with 'aegis secret import ... --force').")
        if generated == 0 and already_done == 0 and not mismatched:
            success("  ✓ Nothing to do")
        print()

    def get_nexus_key_format(self, hostname: str) -> Optional[str]:
        """Format of a host's [nexus-key] manifest entry: "hmac", "ed25519",
        or None if the host has no Nexus key at all yet."""
        manifest_toml = Path(self.aegis_system) / "deploy" / "hosts" / hostname / "secrets.toml"
        if not manifest_toml.exists():
            return None
        with open(manifest_toml, 'rb') as f:
            data = tomllib.load(f)
        nexus_key = data.get('nexus-key')
        if not nexus_key:
            return None
        return nexus_key.get('type') or 'hmac'

    def build_nexus_pubkeys(self) -> None:
        """Move every host from Nexus's legacy HMAC key to an Ed25519
        keypair, for the public-key-authenticated /api/v3 API.

        Idempotent, like every other step here: a host already on ed25519 is
        left alone, so re-running this after the fleet has been migrated is a
        no-op. A host with no key yet gets one in ed25519 directly, rather
        than an hmac key this would just rotate away on the next run.

        Generating the key does not by itself change what a deployed host
        does -- nothing reads it until that host's NixOS config is next
        rebuilt against this repo. Redeploy the Nexus server(s) first when
        that happens, so /api/v3 already recognizes a host's public key
        before that host starts signing with the matching private one
        (AEGIS-MIGRATION.md §3.2).
        """
        info("Migrating Nexus keys to the ed25519 (/api/v3) format...")

        existing_hosts = self.get_aegis_hosts()
        hosts_data = self.entities.get('hosts', {})

        migrated = 0
        already = 0
        failed = []

        for hostname in sorted(hosts_data):
            if hostname not in existing_hosts:
                continue

            if self.get_nexus_key_format(hostname) == 'ed25519':
                already += 1
                continue

            info(f"  → Generating ed25519 Nexus key for {hostname}")
            try:
                run_command(['aegis', 'build', 'nexus-keys', '--host', hostname,
                             '--format', 'ed25519', '--rotate', '--yes'])
                migrated += 1
            except subprocess.CalledProcessError:
                error(f"  ✗ Failed to generate ed25519 Nexus key for {hostname}")
                failed.append(hostname)

        if migrated > 0:
            success(f"  ✓ Migrated {migrated} host(s) to the ed25519 Nexus key format")
            warn(f"     Redeploy the nexus server(s) before any of these hosts, "
                 f"so /api/v3 already knows their public key "
                 f"(AEGIS-MIGRATION.md §3.2).")
        if already > 0:
            success(f"  ✓ {already} host(s) already on the ed25519 format")
        if failed:
            warn(f"  ⚠ Failed for: {' '.join(failed)}")
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
        sites = self.entities.get('sites', {})
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
        self.build_nexus_pubkeys()
        self.add_hosts_to_roles("domain", "domain", "domain-")
        self.add_hosts_to_roles("site", "site", "site-")
        self.add_hosts_to_nebula()
        self.ensure_local_nfs_principals()
        self.ensure_wallfly_secrets()
        self.ensure_mqtt_service_secrets()

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

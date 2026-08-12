{
  description = "Aegis Secrets - Encrypted secrets for infrastructure";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";

    # Admin tools for managing secrets
    aegis-tools-system = {
      url = "github:fudoniten/aegis-tools-system";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Entities repo for host information (as a flake, so we can access its outputs)
    nix-entities.url = "git+ssh://git@github.com/fudoniten/fudo-entities";

    # User secret repos (add as needed)
    # aegis-secrets-niten.url = "github:niten/aegis-secrets-niten";
  };

  outputs = { self, nixpkgs, flake-utils, aegis-tools-system, nix-entities, ...
    }@inputs:
    let
      # Helper to safely read a directory (returns empty if doesn't exist)
      safeReadDir = path:
        if builtins.pathExists path then builtins.readDir path else { };
    in flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        aegis = aegis-tools-system.packages.${system}.aegis;

        # Get the source path of nix-entities for the CLI to use
        entitiesPath = nix-entities.outPath;

        # Generate a JSON file with entity mappings for shell scripts
        # This avoids needing to parse Nix in bash
        entitiesJson = pkgs.writeTextFile {
          name = "entities.json";
          text = builtins.toJSON {
            hosts = builtins.mapAttrs (name: host: {
              inherit (host) domain site;
              realm = if host ? domain && nix-entities.entities.domains
              ? ${host.domain} && nix-entities.entities.domains.${host.domain}
              ? gssapi-realm then
                nix-entities.entities.domains.${host.domain}.gssapi-realm
              else
                null;
              master-key = if host ? aegis && host.aegis ? master-key then
                host.aegis.master-key
              else
                null;
            }) (pkgs.lib.filterAttrs (_: host: host.nixos-system or false)
              nix-entities.entities.hosts);
            domains = builtins.mapAttrs (name: domain: {
              realm =
                if domain ? gssapi-realm then domain.gssapi-realm else null;
            }) nix-entities.entities.domains;
            # Nebula membership, resolved here rather than in the sync
            # script: the entity data and its lookup helpers are both to hand,
            # and a host's overlay address lives in a DNS zone that the script
            # would otherwise have to walk itself.
            #
            # NOT filtered by nixos-system, unlike `hosts` above. A machine
            # managed outside fudo-entities can still hold a mesh identity --
            # that is what `local-key` is for -- so filtering here would
            # silently drop exactly the hosts the enrolment path exists to
            # serve.
            nebula = let
              inherit (nix-entities) entities;
              elib = nix-entities.lib;
              members = pkgs.lib.filterAttrs
                (_: host: (host.nebula-network or null) != null) entities.hosts;
            in {
              networks = builtins.mapAttrs (_: net: {
                inherit (net) cidr zone;
                port = net.port or 4242;
                subdomain = net.subdomain or null;
              }) (entities.nebula.networks or { });

              hosts = builtins.mapAttrs (name: host: {
                inherit (host.nebula-network) network;
                lighthouse = host.nebula-network.lighthouse or false;
                local-key = host.nebula-network.local-key or false;
                groups = host.nebula-network.groups or [ ];
                domain = host.domain or null;
                site = host.site or null;
                profile = host.profile or null;
                # The overlay address, from the network's zone. Null when the
                # host names a network but was never given an address, which
                # is not membership.
                address = elib.getHostNebulaIpv4 name;
                # The routable address a lighthouse is dialled at, from its
                # OWN domain's zone -- not the mesh zone, which would hand out
                # an address unreachable without the tunnel it establishes.
                endpoint-ipv4 = elib.getHostIpv4 name;
              }) members;
            };

            sites = builtins.attrNames nix-entities.entities.sites;
            realms = pkgs.lib.unique (pkgs.lib.filter (r: r != null)
              (pkgs.lib.mapAttrsToList (_: domain:
                if domain ? gssapi-realm then domain.gssapi-realm else null)
                nix-entities.entities.domains));
          };
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [ aegis pkgs.age pkgs.ssh-to-age pkgs.git pkgs.jq ];

          shellHook = ''
            export AEGIS_SYSTEM="$PWD"
            export AEGIS_ENTITIES="${entitiesPath}"
            export AEGIS_ENTITIES_JSON="${entitiesJson}"
            export PATH="$PWD/scripts:$PATH"

            echo ""
            echo "╔═══════════════════════════════════════════════════════════════╗"
            echo "║               Aegis Secrets Development Shell                 ║"
            echo "╚═══════════════════════════════════════════════════════════════╝"
            echo ""
            echo "Available commands:"
            echo "  fudo-sync                          Check all Fudo hosts and build secrets"
            echo "  aegis --help                       Show all aegis commands"
            echo "  aegis check                        Report drift between src/ and deploy/"
            echo "  aegis host add <hostname>          Add a new host to configuration"
            echo "  aegis user add <username>          Add a user and generate their keypair"
            echo "  aegis secret import <name> --host <host>   Import a secret for a machine"
            echo "  aegis secret import <name> --role <role>   ...or for a service, so it follows the role"
            echo "  aegis role add-host <role> <host>  Give a host a role's key and its secrets"
            echo "  aegis build                        Build all secrets (role keys/secrets, SSH, Nexus, keytabs, users)"
            echo "  aegis reencrypt                    Repair recipient drift without new key material"
            echo "  aegis realm list                   Show realms, domains, trusts and members"
            echo "  aegis admin list-keys              Show the admin recipient set"
            echo "  aegis status                       Show what needs building"
            echo "  aegis secret list [host]           List secrets for host(s)"
            echo "  aegis verify <host>                Verify secrets are valid"
            echo ""
            echo "Environment:"
            echo "  AEGIS_SYSTEM:      $AEGIS_SYSTEM"
            echo "  AEGIS_ENTITIES:    $AEGIS_ENTITIES (source path)"
            echo "  AEGIS_ENTITIES_JSON: $AEGIS_ENTITIES_JSON (generated mappings)"
            echo ""
          '';
        };
      }) // {
        # System-independent outputs

        # Expose paths directly (not as derivations)
        # Usage: inputs.aegis-secrets.deployPath
        #
        # Note: despite the name, this directory is not a regenerable build
        # artifact. It holds the ONLY copy of every host's SSH host keys,
        # Nexus keys and DNSSEC private keys. Deleting it and rebuilding mints
        # new identities rather than restoring the old ones.
        deployPath = ./deploy;
        srcPath = ./src;
        keysPath = ./keys;

        # Deprecated alias from when the directory was called build/
        buildPath = ./deploy;

        # Expose paths for specific hosts
        # Usage: inputs.aegis-secrets.hostPath "nostromo"
        hostPath = hostname: ./deploy/hosts + "/${hostname}";

        # List of configured hosts
        # Usage: inputs.aegis-secrets.hosts
        hosts = builtins.attrNames (safeReadDir ./deploy/hosts);

        # Helper functions
        # Usage: inputs.aegis-secrets.lib.hostSecretsPath "nostromo"
        lib = {
          hostSecretsPath = hostname: ./deploy/hosts + "/${hostname}";
          domainSecretsPath = domain:
            ./deploy/domains
            + "/${builtins.replaceStrings [ "." ] [ "_" ] domain}";
          roleKeyPath = role: ./deploy/roles + "/${role}.age";
          kdcPrincipalsPath = realm: ./deploy/kdc + "/${realm}-principals.age";
          kdcRealmKeyPath = realm: ./deploy/kdc + "/${realm}-realm-key.age";
        };
      };
}

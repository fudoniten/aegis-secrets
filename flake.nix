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
            echo "  aegis init-host <hostname>         Add a new host to configuration"
            echo "  aegis add-user <username>          Add a user and generate their keypair"
            echo "  aegis add-secret <host> <name>     Add a custom secret for a host"
            echo "  aegis build                        Build all secrets (SSH keys, Nexus keys, keytabs, user secrets)"
            echo "  aegis status                       Show what needs building"
            echo "  aegis list [host]                  List secrets for host(s)"
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
        # Usage: inputs.aegis-secrets.buildPath
        buildPath = ./build;
        srcPath = ./src;
        keysPath = ./keys;

        # Expose paths for specific hosts
        # Usage: inputs.aegis-secrets.hostPath "nostromo"
        hostPath = hostname: ./build/hosts + "/${hostname}";

        # List of configured hosts
        # Usage: inputs.aegis-secrets.hosts
        hosts = builtins.attrNames (safeReadDir ./build/hosts);

        # Helper functions
        # Usage: inputs.aegis-secrets.lib.hostSecretsPath "nostromo"
        lib = {
          hostSecretsPath = hostname: ./build/hosts + "/${hostname}";
          domainSecretsPath = domain:
            ./build/domains
            + "/${builtins.replaceStrings [ "." ] [ "_" ] domain}";
          roleKeyPath = role: ./build/roles + "/${role}.age";
        };
      };
}

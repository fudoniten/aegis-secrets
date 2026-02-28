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

    # User secret repos (add as needed)
    # aegis-secrets-niten.url = "github:niten/aegis-secrets-niten";
  };

  outputs = { self, nixpkgs, flake-utils, aegis-tools-system, ... }@inputs:
    let
      # Helper to safely read a directory (returns empty if doesn't exist)
      safeReadDir = path:
        if builtins.pathExists path then builtins.readDir path else { };
    in flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        aegis = aegis-tools-system.packages.${system}.aegis;
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [ aegis pkgs.age pkgs.ssh-to-age pkgs.git ];

          shellHook = ''
            export AEGIS_SYSTEM="$PWD"

            echo ""
            echo "╔═══════════════════════════════════════════════════════════════╗"
            echo "║               Aegis Secrets Development Shell                 ║"
            echo "╚═══════════════════════════════════════════════════════════════╝"
            echo ""
            echo "Available commands:"
            echo "  aegis --help           Show all commands"
            echo "  aegis build            Build all secrets"
            echo "  aegis status           Show secrets status"
            echo ""
            echo "Environment:"
            echo "  AEGIS_SYSTEM:   $AEGIS_SYSTEM"
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

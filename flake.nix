{
  description = "Aegis Secrets - Encrypted secrets for infrastructure";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

    # User secret repos (add as needed)
    # aegis-secrets-niten.url = "github:niten/aegis-secrets-niten";
  };

  outputs = { self, nixpkgs, ... }@inputs:
    let
      # Helper to safely read a directory (returns empty if doesn't exist)
      safeReadDir = path:
        if builtins.pathExists path then builtins.readDir path else { };
    in {
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

{ config, pkgs, lib, ... }:

let
  cfg = config.aegis.deriveMasterKey;
in {
  options.aegis.deriveMasterKey = {
    enable = lib.mkEnableOption ''
      Automatically derive the Aegis age master key from the SSH host ed25519 key.

      The aegis build system encrypts host secrets using an age X25519 public key
      that is derived from the host''s SSH ed25519 public key via ssh-to-age. To
      decrypt these secrets at runtime, the aegis module needs the corresponding
      age X25519 private key at masterKeyPath — NOT the raw SSH private key.

      This module creates a systemd service that derives the age private key from
      the SSH host key at boot and stores it at masterKeyPath before aegis-decrypt
      runs. Enable this on any host that uses aegis secrets encrypted by
      aegis-tools-system.
    '';

    sshKeyPath = lib.mkOption {
      type = lib.types.str;
      default = "/etc/ssh/ssh_host_ed25519_key";
      description = ''
        Path to the SSH ed25519 host private key used to derive the age master key.
        This is the same key whose public counterpart is recorded as master_pubkey
        in src/hosts/<hostname>.toml.
      '';
    };

    masterKeyPath = lib.mkOption {
      type = lib.types.str;
      default = "/state/master-key/key";
      description = ''
        Path where the derived age private key will be written. Must match the
        masterKeyPath configured in your aegis NixOS module (default:
        /state/master-key/key).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.aegis-derive-master-key = {
      description = "Derive Aegis age master key from SSH host key";

      # Must run after SSH host keys exist but before aegis-decrypt
      after = [ "local-fs.target" ];
      before = [ "aegis-decrypt.service" "aegis-decrypt-phase2.service" ];
      wantedBy = [ "aegis-decrypt.service" "aegis-decrypt-phase2.service" ];

      unitConfig.ConditionPathExists = cfg.sshKeyPath;

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;

        ExecStart = pkgs.writeShellScript "aegis-derive-master-key" ''
          set -euo pipefail

          key_dir="$(dirname ${lib.escapeShellArg cfg.masterKeyPath})"
          mkdir -p "$key_dir"
          chmod 700 "$key_dir"

          ${pkgs.ssh-to-age}/bin/ssh-to-age -private-key \
            -i ${lib.escapeShellArg cfg.sshKeyPath} \
            -o ${lib.escapeShellArg cfg.masterKeyPath}

          chmod 400 ${lib.escapeShellArg cfg.masterKeyPath}
        '';
      };
    };
  };
}

# Public option surface for the Knot service. Kept separate from configuration
# assembly so each module remains small enough to audit.
{
  lib,
  pkgs,
  cfg,
}:

let
  inherit (lib) mkOption mkEnableOption types;

  optionTypes = import ./knot-option-types.nix { inherit lib cfg; };
  inherit (optionTypes) remoteType zoneSpecType;

in
{

  backend = mkOption {
    type = types.enum [
      "prison"
      "nspawn"
    ];
    default = "prison";
    description = ''
      Which container runs Knot. `prison` is a default-deny podman container
      with no shell, no coreutils and no init of its own; `nspawn` is a full
      NixOS container.
    '';
  };

  stateDir = mkOption {
    type = types.str;
    default = "/var/lib/${cfg.containerName}/knot";
    defaultText = "/var/lib/\${containerName}/knot";
    description = ''
      Host directory holding Knot's journal, timers and KASP database --
      which is where the DNSSEC private keys live, so it must be backed up
      and must survive a redeploy. `prison` backend only.
    '';
  };
  enable = mkEnableOption "a locked-down NixOS container running Knot DNS";

  containerName = mkOption {
    type = types.str;
    default = "knot";
    description = "Name of the NixOS container.";
  };

  role = mkOption {
    type = types.enum [
      "primary"
      "secondary"
    ];
    default = "primary";
    description = ''
      Whether this server is authoritative by file (primary, signs its zones)
      or receives them by transfer (secondary). A secondary loads no zone
      files and does not sign -- signatures come with the transfer.
    '';
  };

  package = mkOption {
    type = types.package;
    default = pkgs.knot-dns;
    defaultText = lib.literalExpression "pkgs.knot-dns";
    description = "Knot DNS package to run.";
  };

  stateVersion = mkOption {
    type = types.str;
    example = "25.11";
    description = "`system.stateVersion` for the container.";
  };

  hostAddress = mkOption {
    type = types.nullOr types.str;
    default = null;
    example = "10.100.0.1";
    description = "IPv4 address of the host end of the container's veth pair.";
  };

  localAddress = mkOption {
    type = types.nullOr types.str;
    default = null;
    example = "10.100.0.2";
    description = "IPv4 address of the container.";
  };

  hostAddress6 = mkOption {
    type = types.nullOr types.str;
    default = null;
    example = "fc00::1";
    description = "IPv6 address of the host end of the container's veth pair.";
  };

  localAddress6 = mkOption {
    type = types.nullOr types.str;
    default = null;
    example = "fc00::2";
    description = "IPv6 address of the container.";
  };

  listen = mkOption {
    type = types.listOf types.str;
    default = [
      "0.0.0.0@53"
      "::@53"
    ];
    description = ''
      Addresses Knot binds inside the container. The container has its own
      network namespace, so binding all addresses here exposes only the
      container's own interfaces.
    '';
  };

  zones = mkOption {
    type = types.attrsOf zoneSpecType;
    default = { };
    description = "Zones this server is authoritative for.";
  };

  remotes = mkOption {
    type = types.attrsOf remoteType;
    default = { };
    description = ''
      All peers, primaries and secondaries alike. `primaries` and
      `secondaries` select from these by name.
    '';
  };

  primaries = mkOption {
    type = types.attrsOf remoteType;
    default = { };
    description = "Peers this server transfers zones *from*. Meaningful when role is \"secondary\".";
  };

  secondaries = mkOption {
    type = types.attrsOf remoteType;
    default = { };
    description = "Peers this server notifies and allows transfers to.";
  };

  tsigKeyFiles = mkOption {
    # types.str, deliberately not types.path.
    #
    # types.path accepts a bare path literal, and nixpkgs' own
    # services.knot builds its config with `"include: ${file}"` -- which,
    # for a path *value*, copies the file into /nix/store with mode 0444.
    # The option that exists to keep TSIG secrets out of the store will
    # cheerfully put one there if you forget the quotes. A string cannot be
    # copied, and the assertion below rejects a store path outright.
    type = types.listOf types.str;
    default = [ ];
    example = [ "/var/lib/secrets/knot-tsig.conf" ];
    description = ''
      Files Knot includes at runtime, holding `key:` sections with their
      secrets. Give locations as strings, and deploy the files by some means
      Nix never sees -- agenix, sops-nix, or plain scp.

      A TSIG secret in the Nix store is a zone-transfer and dynamic-update
      credential readable by every user on the machine, so a store path here
      is an error rather than a warning.
    '';
  };

  dynamicUpdate = mkOption {
    default = { };
    description = ''
      RFC 2136 dynamic update permissions, keyed by a name used to build the
      ACL id. Each entry must name a TSIG key: an update ACL without one
      authorises by address alone, which is forgeable over UDP.
    '';
    type = types.attrsOf (
      types.submodule {
        options = {
          key = mkOption {
            type = types.str;
            description = "TSIG key identifier authorising the update. Its secret belongs in `tsigKeyFiles`.";
          };
          allowedTypes = mkOption {
            type = types.listOf types.str;
            default = [
              "A"
              "AAAA"
              "TXT"
            ];
            example = [ "TXT" ];
            description = ''
              Record types this key may change. The default covers host records
              and ACME challenges. Narrow it to [ "TXT" ] for a key that only
              answers dns-01, so a leaked ACME credential cannot repoint an A
              record. An empty list permits every type, including NS and DNSKEY.
            '';
          };
          allowedOwner = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "_acme-challenge.example.com.";
            description = "Restrict updates to this exact owner name.";
          };
          allowedOwnerMatch = mkOption {
            type = types.enum [ "equal" "sub" ];
            default = "equal";
            description = ''
              Match only `allowedOwner`, or every owner below it. The `sub`
              mode is suitable for a delegated application domain whose key
              must never update sibling names.
            '';
          };
        };
      }
    );
  };

  dnssec = import ./knot-dnssec-options.nix { inherit lib; };

  enableDoT = mkOption {
    type = types.bool;
    default = false;
    description = "Open TCP 853 for DNS over TLS.";
  };

  enableQuic = mkOption {
    type = types.bool;
    default = false;
    description = "Open UDP 853 for DNS over QUIC.";
  };

  logLevel = mkOption {
    type = types.enum [
      "critical"
      "error"
      "warning"
      "notice"
      "info"
      "debug"
    ];
    default = "notice";
    description = "Knot log verbosity for server and zone events.";
  };

  extraAcls = mkOption {
    type = types.listOf types.str;
    default = [ ];
    description = "Additional ACL ids to attach to the default template.";
  };

  extraSettings = mkOption {
    type = types.attrsOf types.anything;
    default = { };
    description = "Merged into the generated Knot settings, for anything not modelled here.";
  };

}

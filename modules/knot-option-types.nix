# Compound option types shared by the Knot service options.
{ lib, cfg }:

let
  inherit (lib) mkOption types;

  remoteType = types.submodule (
    { name, ... }: {
      options = {
        id = mkOption {
          type = types.str;
          default = name;
          description = "Knot remote identifier.";
        };
        address = mkOption {
          type = types.listOf types.str;
          example = [
            "198.51.100.2@53"
            "2001:db8::2@53"
          ];
          description = ''
            Addresses of the peer, in Knot's `address@port` form. Listing both
            an IPv4 and IPv6 address is normal; Knot tries them in order.
          '';
        };
        key = mkOption {
          type = types.nullOr types.str;
          default = null;
          example = "xfr-secondary1";
          description = ''
            Identifier of the TSIG key used with this peer. The key's secret must
            come from `tsigKeyFiles`, never from here -- anything written in this
            option lands in the world-readable Nix store.
          '';
        };
      };
    }
  );

  zoneSpecType = types.submodule {
    options = {
      zone = mkOption {
        type = types.nullOr (types.attrsOf types.anything);
        default = null;
        description = "A dns.nix zone attrset, validated at build time.";
      };
      text = mkOption {
        type = types.nullOr types.lines;
        default = null;
        description = "A literal RFC 1035 zone file, validated at build time.";
      };
      primary = mkOption {
        type = types.bool;
        default = cfg.role == "primary";
        description = ''
          Whether this server holds the zone's contents. Secondary zones are
          declared so Knot transfers them, and contribute no file to storage.
        '';
      };
      dnssec = mkOption {
        type = types.enum [
          "auto"
          "on"
          "off"
        ];
        default = "off";
        description = ''
          Whether kzonecheck enforces DNSSEC checks on the *source* zone.
          Defaults to "off" because Knot signs these zones itself -- the
          source is unsigned by design and there is nothing yet to check.
        '';
      };
    };
  };

in
{
  inherit remoteType zoneSpecType;
}

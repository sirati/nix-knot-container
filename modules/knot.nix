# Knot DNS as a locked-down service: options, zone/config assembly, and the
# checks that do not depend on which backend runs it.
#
# Design constraints, all deliberate:
#
#   * Zone files only. No SQL backend, no Redis/Valkey zone database, no
#     catalog interpretation unless asked for. Knot's zone storage is a
#     read-only Nix store path and its journal is the only mutable copy, which
#     removes an entire class of "what is actually authoritative" question.
#
#   * DNSSEC is not optional. There is no `dnssec.enable = false`. An
#     authoritative server that serves unsigned zones by default is a
#     downgrade waiting to happen, and the cost of signing with Knot's
#     automatic key management is close to zero.
#
#   * The container gets a private network and a firewall that permits port 53
#     and nothing else. A nameserver needs to answer queries and talk to its
#     peers; it does not need outbound anything.

{
  config,
  lib,
  pkgs,
  knotZones,
  ...
}:

let
  cfg = config.services.knotService;

  inherit (lib)
    mkIf
    ;

  tsigKeyRefs = lib.filter (k: k != null) (map (r: r.key) (builtins.attrValues cfg.remotes));

  # RFC 2136 dynamic update. Restricted by TSIG key and, where given, by record
  # type -- an update ACL with no type restriction lets whoever holds the key
  # rewrite NS and DNSKEY records, which is rarely what a DDNS client needs.
  ddnsAcls = lib.mapAttrsToList (
    name: d:
    {
      id = "ddns-${name}";
      key = d.key;
      action = "update";
    }
    // lib.optionalAttrs (d.allowedTypes != [ ]) {
      update-type = d.allowedTypes;
    }
    // lib.optionalAttrs (d.allowedOwner != null) {
      update-owner = "name";
      update-owner-match = d.allowedOwnerMatch;
      update-owner-name = [ d.allowedOwner ];
    }
  ) cfg.dynamicUpdate;

  remoteEntries = lib.mapAttrsToList (
    _: r: { inherit (r) id address; } // lib.optionalAttrs (r.key != null) { inherit (r) key; }
  ) cfg.remotes;

  policyEntry = {
    id = "signing";
    algorithm = cfg.dnssec.algorithm;
    nsec3 = cfg.dnssec.nsec3;
    ksk-lifetime = cfg.dnssec.kskLifetime;
    zsk-lifetime = cfg.dnssec.zskLifetime;
    propagation-delay = cfg.dnssec.propagationDelay;
    rrsig-lifetime = cfg.dnssec.signatureLifetime;
    rrsig-refresh = cfg.dnssec.signatureRefresh;
  }
  // lib.optionalAttrs cfg.dnssec.nsec3 {
    # RFC 9276: iterations above 0 buy nothing and cost the server work an
    # attacker can amplify.
    nsec3-iterations = 0;
  }
  // lib.optionalAttrs cfg.dnssec.singleType {
    single-type-signing = true;
  };

  # Role-specific template settings. The storage path, zonefile-load,
  # journal-content and zonefile-sync come from knot-zones, which knows how the
  # zones were built; restating them here would be a second source of truth.
  templateExtras =
    lib.optionalAttrs (cfg.role == "primary") {
      dnssec-signing = true;
      dnssec-policy = "signing";
      notify = map (r: r.id) (builtins.attrValues cfg.secondaries);
      acl = map (a: a.id) ddnsAcls ++ cfg.extraAcls;
    }
    // lib.optionalAttrs (cfg.role == "secondary") {
      master = map (r: r.id) (builtins.attrValues cfg.primaries);
      # A secondary holds no zone file: contents arrive by transfer and live in
      # the journal, so there is nothing in the store for it to load.
      zonefile-load = "none";
      journal-content = "all";
    };

  # `user` and `logTarget` are the two settings that depend on what is running
  # the server. A prison has no `knot` account to drop to -- the container is
  # already unprivileged -- and no syslog to write to.
  baseSettings =
    { user, logTarget }:
    lib.recursiveUpdate {
      server = {
        rundir = "/run/knot";

        listen = cfg.listen;
        # Derives transfer/notify ACLs from the configured remotes, so a peer
        # listed once does not also need a hand-written acl block.
        automatic-acl = true;
      }
      // lib.optionalAttrs (user != null) { inherit user; };

      log = [
        {
          target = logTarget;
          server = cfg.logLevel;
          zone = cfg.logLevel;
        }
      ];

      database = {
        storage = "/var/lib/knot";
        journal-db = "/var/lib/knot/journal";
        kasp-db = "/var/lib/knot/keys";
        timer-db = "/var/lib/knot/timers";
      };

      remote = remoteEntries;
      acl = ddnsAcls;
      policy = [ policyEntry ];
    } cfg.extraSettings;

  # Zones, storage and the complete configuration in one step. `configFile` is
  # the output of a derivation that ran `knotc conf-check` first, so the file
  # Knot reads cannot exist unless the configuration validated.
  mkSettings =
    {
      keyFiles,
      user ? "knot:knot",
      logTarget ? "syslog",
      settingsOverride ? { },
      templateOverride ? { },
    }:
    knotZones.mkZones {
      name = "${cfg.containerName}-zones";
      zones = lib.mapAttrs (_: z: {
        inherit (z)
          zone
          text
          primary
          dnssec
          ;
      }) cfg.zones;
      template = lib.recursiveUpdate templateExtras templateOverride;
      settings = lib.recursiveUpdate (baseSettings { inherit user logTarget; }) settingsOverride;
      inherit keyFiles;
    };

  prisonSecretPath = f: "/secrets/${baseNameOf f}";
  built = mkSettings (
    if cfg.backend == "prison" then
      {
        keyFiles = map prisonSecretPath cfg.tsigKeyFiles;
        user = null;
        logTarget = "stdout";
        # Fresh setup seeds the journal from the zone files. Thereafter the
        # journal is authoritative; a separate pre-start reconciliation applies
        # only declarative record changes, preserving DDNS records.
        templateOverride = lib.optionalAttrs cfg.freshInit.enable {
          zonefile-load = "none";
        };
      }
    else
      { keyFiles = cfg.tsigKeyFiles; }
  );

  # Check only runtime metadata that a derivation cannot know. The generated
  # configuration was already checked with placeholder keys during the build;
  # this process deliberately never opens or parses the real secret.
  mkPreflight = pkgs.writeShellScript "knot-tsig-preflight" ''
    set -eu
    fail() { echo "knot-service: $*" >&2; exit 1; }

    for f in ${lib.escapeShellArgs cfg.tsigKeyFiles}; do
      [ -e "$f" ] || fail "TSIG key file $f does not exist. It is deployed outside Nix, so nothing in the build could have caught this."
      [ -f "$f" ] || fail "TSIG key file $f is not a regular file."

      real=$(${pkgs.coreutils}/bin/readlink -f "$f")
      case "$real" in
        ${builtins.storeDir}/*)
          fail "TSIG key file $f resolves to $real, inside the Nix store, where it is world-readable."
          ;;
      esac

      perm=$(${pkgs.coreutils}/bin/stat -Lc '%a' "$f")
      if [ $(( 8#$perm & 8#004 )) -ne 0 ]; then
        fail "TSIG key file $f is world-readable (mode $perm). Remove world access and grant read access only to knotd."
      fi

    done
  '';

in
{
  options.services.knotService = (import ./knot-options.nix {
    inherit lib pkgs cfg;
  }) // {
    generatedConfigFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = if cfg.enable then toString built.configFile else null;
      readOnly = true;
      description = "Store path of the validated configuration read by knotd, or null when disabled.";
    };
    generatedZoneStorage = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = if cfg.enable then map toString ([ built.storage ] ++ builtins.attrValues built.files) else [ ];
      readOnly = true;
      description = ''
        Store paths of the generated zone storage directory and its zone files.
        The storage directory contains links to the separately built zone files.
      '';
    };
    generatedZoneFiles = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = if cfg.enable then
        lib.mapAttrsToList
          (name: dir: "${dir}/${lib.removeSuffix "." name}.zone")
          built.files
      else [ ];
      readOnly = true;
      description = "Regular generated zone files, suitable for per-file configuration snapshots.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = !cfg.freshInit.enable || (cfg.role == "primary" && cfg.backend == "prison");
        message = "services.knotService.freshInit requires a primary with the prison backend.";
      }
      {
        assertion = builtins.all (p: !(lib.hasPrefix builtins.storeDir p)) cfg.tsigKeyFiles;
        message = ''
          services.knotService: a tsigKeyFiles entry points into the Nix store.

          Everything in the store is world-readable, so a TSIG secret there is a
          zone-transfer and dynamic-update credential for every user on this
          machine. This is what happens when a bare path literal is used, since
          Nix copies those into the store on interpolation. Quote the path and
          deploy the file outside Nix:

            tsigKeyFiles = [ "/var/lib/secrets/knot-tsig.conf" ];
        '';
      }
      {
        assertion = builtins.all (p: lib.hasPrefix "/" p) cfg.tsigKeyFiles;
        message = "services.knotService: tsigKeyFiles entries must be absolute paths; Knot reads them at runtime.";
      }
      {
        assertion = cfg.role == "secondary" -> cfg.primaries != { };
        message = "services.knotService: role is \"secondary\" but no primaries are configured, so no zone would ever be transferred.";
      }
      {
        assertion = cfg.role == "primary" -> cfg.zones != { };
        message = "services.knotService: role is \"primary\" but no zones are configured.";
      }
      {
        assertion = cfg.dynamicUpdate == { } || cfg.tsigKeyFiles != [ ];
        message = ''
          services.knotService: dynamicUpdate is configured but tsigKeyFiles is empty.

          The referenced TSIG keys have to be defined somewhere, and their
          secrets must not go in the Nix store. Point tsigKeyFiles at a file
          deployed outside Nix.
        '';
      }
      {
        assertion = builtins.all (r: r.key != null || cfg.tsigKeyFiles != [ ]) (
          builtins.attrValues cfg.secondaries
        );
        message = ''
          services.knotService: a secondary has no TSIG key.

          Zone transfers authorised only by address are forgeable, and an
          unauthenticated AXFR hands over the whole zone. Set `key` on each
          secondary and supply the secret via tsigKeyFiles.
        '';
      }
    ];

    # Both backends build the same configuration; they differ only in where
    # the key files are readable from, so the settings are a function of that.
    _module.args.knotLib = { inherit mkSettings mkPreflight built prisonSecretPath; };
  };
}

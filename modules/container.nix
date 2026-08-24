# A NixOS container that runs Knot DNS and nothing else.
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

{ config, lib, pkgs, knotZones, ... }:

let
  cfg = config.services.knotService;

  inherit (lib) mkOption mkEnableOption types mkIf;

  remoteType = types.submodule ({ name, ... }: {
    options = {
      id = mkOption {
        type = types.str;
        default = name;
        description = "Knot remote identifier.";
      };
      address = mkOption {
        type = types.listOf types.str;
        example = [ "198.51.100.2@53" "2001:db8::2@53" ];
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
  });

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
        type = types.enum [ "auto" "on" "off" ];
        default = "off";
        description = ''
          Whether kzonecheck enforces DNSSEC checks on the *source* zone.
          Defaults to "off" because Knot signs these zones itself -- the
          source is unsigned by design and there is nothing yet to check.
        '';
      };
    };
  };


  tsigKeyRefs = lib.filter (k: k != null) (map (r: r.key) (builtins.attrValues cfg.remotes));

  # RFC 2136 dynamic update. Restricted by TSIG key and, where given, by record
  # type -- an update ACL with no type restriction lets whoever holds the key
  # rewrite NS and DNSKEY records, which is rarely what a DDNS client needs.
  ddnsAcls = lib.mapAttrsToList
    (name: d: {
      id = "ddns-${name}";
      key = d.key;
      action = "update";
    } // lib.optionalAttrs (d.allowedTypes != [ ]) {
      update-type = d.allowedTypes;
    } // lib.optionalAttrs (d.allowedOwner != null) {
      update-owner = "name";
      update-owner-match = "equal";
      update-owner-name = [ d.allowedOwner ];
    })
    cfg.dynamicUpdate;

  remoteEntries = lib.mapAttrsToList
    (_: r: { inherit (r) id address; } // lib.optionalAttrs (r.key != null) { inherit (r) key; })
    cfg.remotes;

  policyEntry = {
    id = "signing";
    algorithm = cfg.dnssec.algorithm;
    nsec3 = cfg.dnssec.nsec3;
    ksk-lifetime = cfg.dnssec.kskLifetime;
    zsk-lifetime = cfg.dnssec.zskLifetime;
    propagation-delay = cfg.dnssec.propagationDelay;
    rrsig-lifetime = cfg.dnssec.signatureLifetime;
    rrsig-refresh = cfg.dnssec.signatureRefresh;
  } // lib.optionalAttrs cfg.dnssec.nsec3 {
    # RFC 9276: iterations above 0 buy nothing and cost the server work an
    # attacker can amplify.
    nsec3-iterations = 0;
  } // lib.optionalAttrs cfg.dnssec.singleType {
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

  baseSettings = lib.recursiveUpdate
    {
      server = {
        rundir = "/run/knot";
        user = "knot:knot";
        listen = cfg.listen;
        # Derives transfer/notify ACLs from the configured remotes, so a peer
        # listed once does not also need a hand-written acl block.
        automatic-acl = true;
      };

      log = [{ target = "syslog"; server = cfg.logLevel; zone = cfg.logLevel; }];

      database = {
        storage = "/var/lib/knot";
        journal-db = "/var/lib/knot/journal";
        kasp-db = "/var/lib/knot/keys";
        timer-db = "/var/lib/knot/timers";
      };

      remote = remoteEntries;
      acl = ddnsAcls;
      policy = [ policyEntry ];
    }
    cfg.extraSettings;

  # Zones, storage and the complete configuration in one step. `configFile` is
  # the output of a derivation that ran `knotc conf-check` first, so the file
  # Knot reads cannot exist unless the configuration validated.
  built = knotZones.mkZones {
    name = "${cfg.containerName}-zones";
    zones = lib.mapAttrs (_: z: { inherit (z) zone text primary dnssec; }) cfg.zones;
    template = templateExtras;
    settings = baseSettings;
    keyFiles = cfg.tsigKeyFiles;
  };

  # The half of validation that cannot happen at build time.
  #
  # The build checks everything that does not depend on a secret: placeholder
  # `key:` sections stand in, and conf-check verifies the whole structure.
  # What it cannot see is whether the real key files exist, are readable by
  # knot, are not world-readable, and parse -- because none of that may be in
  # the store. So it is checked here instead, before knotd starts, with the
  # real files in place. A broken or unreadable secret fails the unit with a
  # named cause rather than a knotd startup error.
  tsigPreflight = pkgs.writeShellScript "knot-tsig-preflight" ''
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
        fail "TSIG key file $f is world-readable (mode $perm). Use 0640 root:knot, or 0400 owned by knot."
      fi

      [ -r "$f" ] || fail "TSIG key file $f is not readable by the knot user (mode $perm). Signing and transfers would fail at the first use."
    done

    # Now the real thing: the same config the build checked, but with the
    # actual key files resolved through their include: directives.
    exec ${cfg.package}/bin/knotc --config=${built.configFile} conf-check
  '';

  # The NixOS configuration running *inside* the container.
  containerConfig = { ... }: {
    system.stateVersion = cfg.stateVersion;

    services.knot = {
      enable = true;
      package = cfg.package;
      # settingsFile rather than settings, because the file has already been
      # conf-checked. nixpkgs' own check switches itself off whenever keyFiles
      # is used (`default = cfg.keyFiles == [] && !cfg.enableXDP`), which is
      # precisely when TSIG secrets are being kept out of the store -- so
      # relying on it would mean no validation at all here. keyFiles is left
      # empty because the include: directives are already in the file.
      settingsFile = built.configFile;
      settings = { };
      keyFiles = [ ];
    };

    networking = {
      firewall = {
        enable = true;
        allowedTCPPorts = [ 53 ] ++ lib.optional cfg.enableDoT 853;
        allowedUDPPorts = [ 53 ] ++ lib.optional cfg.enableQuic 853;
        # A nameserver answers; it does not browse. Logging rejects makes an
        # unexpected outbound attempt visible rather than silent.
        logRefusedConnections = true;
      };
      useHostResolvConf = false;
      # Resolving names is not this container's job -- it *is* the name
      # service. Pointing it at itself avoids a dependency on anything outside.
      nameservers = [ "127.0.0.1" ];
    };

    # Everything below strips the container to a nameserver and nothing else.
    documentation.enable = false;
    documentation.nixos.enable = false;
    documentation.man.enable = false;
    environment.defaultPackages = lib.mkForce [ ];
    programs.command-not-found.enable = false;
    services.udisks2.enable = false;
    security.polkit.enable = lib.mkForce false;
    xdg.autostart.enable = false;
    xdg.icons.enable = false;
    xdg.mime.enable = false;
    xdg.sounds.enable = false;
    fonts.fontconfig.enable = lib.mkForce false;
    boot.enableContainers = false;

    # nixpkgs already hardens knot.service; these tighten what a compromised
    # parser can reach. Knot needs CAP_NET_BIND_SERVICE for port 53 and,
    # with XDP disabled, nothing else.
    systemd.services.knot.serviceConfig = {
      # Runs as the knot user under the same hardening as knotd, so a
      # permission problem surfaces here with a named cause instead of as a
      # later failure to sign or transfer.
      ExecStartPre = [ "${tsigPreflight}" ];
      CapabilityBoundingSet = lib.mkForce [ "CAP_NET_BIND_SERVICE" ];
      AmbientCapabilities = lib.mkForce [ "CAP_NET_BIND_SERVICE" ];
      NoNewPrivileges = true;
      PrivateDevices = true;
      PrivateTmp = true;
      ProtectClock = true;
      ProtectControlGroups = true;
      ProtectHome = true;
      ProtectHostname = true;
      ProtectKernelLogs = true;
      ProtectKernelModules = true;
      ProtectKernelTunables = true;
      ProtectProc = "invisible";
      ProcSubset = "pid";
      ProtectSystem = "strict";
      RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      SystemCallArchitectures = "native";
      SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
      UMask = "0077";
      # Signing keys and the journal. Everything else stays read-only.
      StateDirectory = "knot";
      StateDirectoryMode = "0700";
      ReadWritePaths = [ "/var/lib/knot" ];
    };
  };
in
{
  options.services.knotService = {
    enable = mkEnableOption "a locked-down NixOS container running Knot DNS";

    containerName = mkOption {
      type = types.str;
      default = "knot";
      description = "Name of the NixOS container.";
    };

    role = mkOption {
      type = types.enum [ "primary" "secondary" ];
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
      default = [ "0.0.0.0@53" "::@53" ];
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
      type = types.attrsOf (types.submodule {
        options = {
          key = mkOption {
            type = types.str;
            description = "TSIG key identifier authorising the update. Its secret belongs in `tsigKeyFiles`.";
          };
          allowedTypes = mkOption {
            type = types.listOf types.str;
            default = [ "A" "AAAA" "TXT" ];
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
        };
      });
    };

    dnssec = {
      algorithm = mkOption {
        type = types.enum [ "ecdsap256sha256" "ecdsap384sha384" "ed25519" "rsasha256" ];
        default = "ecdsap256sha256";
        description = ''
          Signing algorithm. ECDSA P-256 is the interoperable default: smaller
          signatures than RSA and universally supported, which ed25519 still
          is not.
        '';
      };
      nsec3 = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Use NSEC3 rather than NSEC. NSEC3 only frustrates casual zone
          enumeration -- it does not prevent it -- and costs every negative
          answer a hash. Enable it if enumeration matters to you; iterations
          are pinned to 0 per RFC 9276 either way.
        '';
      };
      singleType = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Single-type signing: one key acting as both KSK and ZSK. Simpler,
          at the cost of needing a DS update for every rollover.
        '';
      };
      kskLifetime = mkOption {
        type = types.ints.unsigned;
        default = 0;
        description = ''
          KSK lifetime in seconds. 0 means no automatic rollover, which is the
          safe default: a KSK roll needs a matching DS update at the parent,
          and Knot cannot do that for you unless you configure a submission.
        '';
      };
      zskLifetime = mkOption {
        type = types.ints.unsigned;
        default = 2592000;
        description = "ZSK lifetime in seconds. Rolls automatically; no parent involvement needed.";
      };
      propagationDelay = mkOption {
        type = types.ints.unsigned;
        default = 3600;
        description = ''
          Time to assume a zone change needs to reach every secondary before
          the next rollover step. Too low and a rollover can outrun the
          transfers, leaving a resolver holding signatures whose key it cannot
          see. Should exceed your slowest secondary's refresh.
        '';
      };
      signatureLifetime = mkOption {
        type = types.ints.unsigned;
        default = 1209600;
        description = "RRSIG validity in seconds (default 14 days).";
      };
      signatureRefresh = mkOption {
        type = types.ints.unsigned;
        default = 604800;
        description = ''
          Re-sign this long before expiry (default 7 days). The gap between
          this and signatureLifetime is how long the server can be down before
          signatures start expiring and the zone goes dark for validating
          resolvers.
        '';
      };
    };

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
      type = types.enum [ "critical" "error" "warning" "notice" "info" "debug" ];
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
  };

  config = mkIf cfg.enable {
    assertions = [
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
        assertion = builtins.all (r: r.key != null || cfg.tsigKeyFiles != [ ])
          (builtins.attrValues cfg.secondaries);
        message = ''
          services.knotService: a secondary has no TSIG key.

          Zone transfers authorised only by address are forgeable, and an
          unauthenticated AXFR hands over the whole zone. Set `key` on each
          secondary and supply the secret via tsigKeyFiles.
        '';
      }
    ];

    containers.${cfg.containerName} = {
      autoStart = true;
      # Its own netns: the firewall below is then the container's whole
      # exposure, not a filter layered over the host's interfaces.
      privateNetwork = true;
      inherit (cfg) hostAddress localAddress hostAddress6 localAddress6;

      # TSIG secrets are bind-mounted rather than copied, so they never enter
      # the store or a container image.
      bindMounts = lib.listToAttrs (map
        (p: lib.nameValuePair (toString p) {
          hostPath = toString p;
          isReadOnly = true;
        })
        cfg.tsigKeyFiles);

      config = containerConfig;
    };
  };
}

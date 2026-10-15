# The prison backend: Knot in a default-deny podman container.
#
# No shell, no coreutils, no package manager and no init of its own -- what
# knotd can reach is its own closure and nothing else. Everything
# domain-specific lives in knot.nix; this is only the container.

{
  config,
  lib,
  pkgs,
  knotLib,
  prison,
  ...
}:

let
  cfg = config.services.knotService;
  inherit (lib) mkIf;

  # Where each key file is readable from *inside* the container. It is bound
  # there one file at a time rather than by its directory, so the service is
  # given its own secret and not whatever else the host keeps alongside it.
  inherit (knotLib) built;
  secretPath = knotLib.prisonSecretPath;

  tsigPreflight = knotLib.mkPreflight;

  # A remote is written `address@port`; egress is opened to exactly those.
  splitRemote =
    a:
    let
      m = builtins.match "([^@]+)@([0-9]+)" a;
    in
    if m == null then
      {
        address = a;
        port = 53;
      }
    else
      {
        address = builtins.elemAt m 0;
        port = lib.toInt (builtins.elemAt m 1);
      };

  peerAddresses = lib.unique (lib.concatMap (r: r.address) (builtins.attrValues cfg.remotes));

  # A primary sends NOTIFY and a secondary asks for a transfer; both are
  # outbound to a peer's DNS port and nothing else leaves. In particular no
  # recursive resolver: knotd holds the zone keys, and a resolver it may
  # query is a channel out of the prison. The parent's DS is checked outside.
  egressTargets = lib.concatMap (
    a:
    let
      t = splitRemote a;
    in
    [
      {
        inherit (t) address port;
        protocol = "udp";
      }
      {
        inherit (t) address port;
        protocol = "tcp";
      }
    ]
  ) peerAddresses;

  tcpPorts = [ 53 ] ++ lib.optional cfg.enableDoT 853;
  udpPorts = [ 53 ] ++ lib.optional cfg.enableQuic 853;

  knotd = prison.mkPrisonService {
    name = "knotd";
    exec = [
      "${cfg.package}/bin/knotd"
      "--config"
      "/config/knot.conf"
    ];
    uid = 1000;

    # Binding port 53. Nothing else is granted.
    capabilities.netBindService = true;

    # The zone files are a store path referenced only from the configuration,
    # so the store view has to be told about them or the mount will not carry
    # them.
    packages = [ built.storage ];

    # The control socket. A tmpfs, because nothing in it needs to outlive the
    # container.
    state = [
      {
        path = "/run/knot";
        size = "8M";
      }
    ];

    persist =
      # The journal, the timers, and the KASP database -- which holds the
      # DNSSEC private keys Knot generates itself. Losing this is losing the
      # zone's keys, so it is a host directory rather than a tmpfs.
      [
        {
          host = cfg.stateDir;
          path = "/var/lib/knot";
        }
      ]
      # TSIG secrets: read-only, one file each, never in the store.
      ++ map (f: {
        host = f;
        path = secretPath f;
        readOnly = true;
        file = true;
      }) cfg.tsigKeyFiles;

    config = {
      "knot.conf" = built.configFile;
    };

    # Journal-backed primaries reconcile static zone changes in the prepare
    # unit, so a changed generation must start that unit before knotd again.
    reload = if cfg.freshInit.enable then null else { signal = "SIGHUP"; };
  };

  freshInitHelper = pkgs.rustPlatform.buildRustPackage {
    pname = "knot-fresh-init";
    version = "0.1.0";
    src = ../setup-helper;
    cargoLock.lockFile = ../setup-helper/Cargo.lock;
  };

  setupBuilt = knotLib.mkSettings {
    keyFiles = map secretPath cfg.tsigKeyFiles;
    user = null;
    logTarget = "stdout";
    settingsOverride.server = {
      listen = [ "127.0.0.1@1053" ];
      rundir = "/run/knot";
    };
    templateOverride.notify = [ ];
  };

  prepareBuilt = knotLib.mkSettings {
    keyFiles = map secretPath cfg.tsigKeyFiles;
    user = null;
    logTarget = "stdout";
    settingsOverride.server = {
      listen = [ "127.0.0.1@1053" ];
      rundir = "/run/knot";
    };
    templateOverride = {
      notify = [ ];
      zonefile-load = "none";
    };
  };

  bootstrapBuilt = lib.mapAttrs (name: zone: knotLib.mkSettings {
    keyFiles = map secretPath cfg.tsigKeyFiles;
    user = null;
    logTarget = "stdout";
    zonesOverride = { ${name} = zone; };
    settingsOverride.server = {
      listen = [ "127.0.0.1@1053" ];
      rundir = "/run/knot";
    };
    templateOverride.notify = [ ];
  }) cfg.zones;

  zoneArgs = builtConfig: lib.mapAttrsToList
    (name: dir: "${lib.removeSuffix "." name}.=${dir}/${lib.removeSuffix "." name}.zone=${bootstrapBuilt.${name}.configFile}")
    builtConfig.files;

  initArgs = mode: builtConfig: [
    "${freshInitHelper}/bin/knot-fresh-init"
    mode
    "${cfg.package}/bin/knotd"
    "${cfg.package}/bin/knotc"
    "${cfg.package}/bin/keymgr"
    "${cfg.package}/bin/kzonecheck"
    "/config/knot.conf"
    "/var/lib/knot"
    (if cfg.dnssec.singleType then "single" else "split")
  ] ++ zoneArgs builtConfig;

  stateMounts = [ { host = cfg.stateDir; path = "/var/lib/knot"; } ]
    ++ map (f: {
      host = f;
      path = secretPath f;
      readOnly = true;
      file = true;
    }) cfg.tsigKeyFiles;

  # The two setup tasks, each a run of the fresh-init helper to completion.
  # `oneshot` makes the unit end with the helper's exit status; a detached
  # run had the unit succeed once the container started, and its cleanup
  # then removed the container while the helper still ran.
  setupTask =
    name: mode: builtConfig:
    prison.mkPrisonService {
      inherit name;
      exec = initArgs mode builtConfig;
      uid = 1000;
      oneshot = true;
      packages = [ cfg.package builtConfig.storage ]
        ++ lib.concatMap (x: [ x.storage x.configFile ]) (builtins.attrValues bootstrapBuilt);
      state = [ { path = "/run/knot"; size = "8M"; } ];
      persist = stateMounts;
      config."knot.conf" = builtConfig.configFile;
    };

  initialize = setupTask "initialize" "initialize" setupBuilt;
  prepare = setupTask "prepare" "reconcile" prepareBuilt;
in
{
  config = mkIf (cfg.enable && cfg.backend == "prison") {
    services.prisons.${cfg.containerName} = prison.mkPrison {
      name = cfg.containerName;
      services = { inherit knotd; } // lib.optionalAttrs cfg.freshInit.enable { inherit initialize prepare; };
      listen = {
        tcp = tcpPorts;
        udp = udpPorts;
      };
      egress =
        if egressTargets == [ ] then
          {
            mode = "none";
            targets = [ ];
            lan = [ ];
          }
        else
          {
            mode = "targets";
            targets = egressTargets;
            lan = [ ];
          };
    };

    # The half of validation that cannot happen at build time, run on the host
    # because that is where the secrets are. The prison unit starts the
    # containers, so this gates it.
    systemd.services = {
      "${cfg.containerName}" = {
        path = [ "/run/wrappers" ];
        serviceConfig.ExecStartPre = lib.mkBefore [ "${tsigPreflight}" ];
      };
      "${cfg.containerName}-knotd".path = [ "/run/wrappers" ];
    } // lib.optionalAttrs cfg.freshInit.enable {
      # The setup tasks are prison oneshots: each unit ends with its helper.
      # Neither runs at boot; setup and knotd ask for them.
      "${cfg.containerName}-initialize" = {
        path = [ "/run/wrappers" ];
        # Fresh setup generates keys and seeds the journal; a hang must still
        # end in a failed unit rather than a setup that never finishes.
        serviceConfig.TimeoutStartSec = "30min";
      };
      # knotd requires prepare, so a prepare that gives up leaves the zone
      # unserved until someone intervenes. It retries instead, with backoff
      # and a start limit so a persistent fault still ends in a failed unit.
      # Every retry re-runs the prison's store-view check, which replaces a
      # view left serving an older closure. RestartMode=direct keeps the unit
      # activating between attempts, so knotd's start waits for the retries
      # instead of failing on the first one.
      "${cfg.containerName}-prepare" = {
        path = [ "/run/wrappers" ];
        startLimitIntervalSec = 1800;
        startLimitBurst = 6;
        serviceConfig = {
          Restart = lib.mkForce "on-failure";
          RestartMode = "direct";
          RestartSec = "5s";
          RestartSteps = 4;
          RestartMaxDelaySec = "2min";
          TimeoutStartSec = "10min";
        };
      };
      "${cfg.containerName}-knotd" = {
        path = [ "/run/wrappers" ];
        requires = [ "${cfg.containerName}-prepare.service" ];
        after = [ "${cfg.containerName}-prepare.service" ];
      };
      "${cfg.containerName}-setup" = {
        description = "Initialize Knot state for ${cfg.containerName}";
        requires = [ "${cfg.containerName}-initialize.service" ];
        after = [ "${cfg.containerName}-initialize.service" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.coreutils}/bin/true";
        };
      };
    };
  };
}

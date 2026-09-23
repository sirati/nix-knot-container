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

  # A primary sends NOTIFY, a secondary asks for a transfer; both are outbound
  # to a peer's DNS port and nothing else leaves.
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
    settingsOverride.server.listen = [ "127.0.0.1@1053" ];
    templateOverride.notify = [ ];
  };

  prepareBuilt = knotLib.mkSettings {
    keyFiles = map secretPath cfg.tsigKeyFiles;
    user = null;
    logTarget = "stdout";
    settingsOverride.server.listen = [ "127.0.0.1@1053" ];
    templateOverride = {
      notify = [ ];
      zonefile-load = "none";
    };
  };

  zoneArgs = builtConfig: lib.mapAttrsToList
    (name: dir: "${lib.removeSuffix "." name}.=${dir}/${lib.removeSuffix "." name}.zone")
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

  initialize = prison.mkPrisonService {
    name = "initialize";
    exec = initArgs "initialize" setupBuilt;
    uid = 1000;
    packages = [ cfg.package setupBuilt.storage ];
    state = [ { path = "/run/knot"; size = "8M"; } ];
    persist = stateMounts;
    config."knot.conf" = setupBuilt.configFile;
  };

  prepare = prison.mkPrisonService {
    name = "prepare";
    exec = initArgs "reconcile" prepareBuilt;
    uid = 1000;
    packages = [ cfg.package prepareBuilt.storage ];
    state = [ { path = "/run/knot"; size = "8M"; } ];
    persist = stateMounts;
    config."knot.conf" = prepareBuilt.configFile;
  };
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
      "${cfg.containerName}".serviceConfig.ExecStartPre = lib.mkBefore [
        "${tsigPreflight}"
      ];
    } // lib.optionalAttrs cfg.freshInit.enable {
      "${cfg.containerName}-initialize" = {
        wantedBy = lib.mkForce [ ];
        serviceConfig = {
          Type = lib.mkForce "oneshot";
          Restart = lib.mkForce "no";
        };
      };
      "${cfg.containerName}-prepare" = {
        wantedBy = lib.mkForce [ ];
        serviceConfig = {
          Type = lib.mkForce "oneshot";
          Restart = lib.mkForce "no";
        };
      };
      "${cfg.containerName}-knotd" = {
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

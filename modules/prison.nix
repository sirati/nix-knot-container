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

    # knotd re-reads its configuration and zones on SIGHUP, so a change to the
    # config directory is a reload rather than a restart.
    reload = {
      signal = "SIGHUP";
    };
  };
in
{
  config = mkIf (cfg.enable && cfg.backend == "prison") {
    services.prisons.${cfg.containerName} = prison.mkPrison {
      name = cfg.containerName;
      services = { inherit knotd; };
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
    systemd.services."${cfg.containerName}".serviceConfig.ExecStartPre = lib.mkBefore [
      "${tsigPreflight}"
    ];
  };
}

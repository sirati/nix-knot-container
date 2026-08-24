# The systemd-nspawn backend: a full NixOS container running Knot.
#
# Everything domain-specific lives in knot.nix; this is only the container.

{ config, lib, pkgs, knotLib, ... }:

let
  cfg = config.services.knotService;
  inherit (lib) mkIf;

  # nspawn bind-mounts each key file at the path it has on the host, so the
  # config can include it by that same path.
  built = knotLib.mkSettings { keyFiles = cfg.tsigKeyFiles; };
  tsigPreflight = knotLib.mkPreflight built.configFile;

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
  config = mkIf (cfg.enable && cfg.backend == "nspawn") {
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

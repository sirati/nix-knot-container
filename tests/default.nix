{
  pkgs,
  nixpkgs,
  system,
  lib,
  knotZones,
  module,
}:

let
  # `boot.isContainer` lets a NixOS system evaluate without a bootloader or
  # filesystems, which is all that is needed to read back generated config.
  evalHost =
    extra:
    nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        module
        {
          boot.isContainer = true;
          system.stateVersion = "25.11";
          networking.hostName = "knot-test-host";
        }
        extra
      ];
    };

  primaryHost = evalHost {
    services.knotService = {
      enable = true;
      backend = "nspawn";
      stateVersion = "25.11";
      role = "primary";
      hostAddress = "10.100.0.1";
      localAddress = "10.100.0.2";

      zones."example.com".zone = {
        SOA = {
          nameServer = "ns1.example.com.";
          adminEmail = "hostmaster@example.com";
          serial = 1;
        };
        NS = [
          "ns1.example.com."
          "ns2.example.com."
        ];
        A = [ "203.0.113.1" ];
        subdomains = {
          ns1.A = [ "203.0.113.2" ];
          ns2.A = [ "203.0.113.3" ];
        };
      };

      remotes.secondary1 = {
        address = [ "198.51.100.2@53" ];
        key = "xfr-secondary1";
      };
      secondaries.secondary1 = {
        address = [ "198.51.100.2@53" ];
        key = "xfr-secondary1";
      };

      dynamicUpdate.acme = {
        key = "acme-updater";
        allowedTypes = [ "TXT" ];
        allowedOwner = "_acme-challenge.example.com.";
      };
      dynamicUpdate.relay = {
        key = "relay-updater";
        allowedTypes = [ "TXT" ];
        allowedOwner = "noreply.example.com.";
        allowedOwnerMatch = "sub";
      };

      tsigKeyFiles = [ "/var/lib/secrets/knot-tsig.conf" ];
    };
  };

  prisonHost = evalHost {
    services.knotService = {
      enable = true;
      role = "primary";

      zones."example.com".zone = {
        SOA = {
          nameServer = "ns1.example.com.";
          adminEmail = "hostmaster@example.com";
          serial = 1;
        };
        NS = [ "ns1.example.com." ];
        A = [ "203.0.113.1" ];
        subdomains.ns1.A = [ "203.0.113.2" ];
      };

      remotes.secondary1 = {
        address = [ "198.51.100.2@53" ];
        key = "xfr-secondary1";
      };
      secondaries.secondary1 = {
        address = [ "198.51.100.2@53" ];
        key = "xfr-secondary1";
      };
      tsigKeyFiles = [ "/var/lib/secrets/knot-tsig.conf" ];
    };
  };

  freshHost = evalHost {
    services.knotService = {
      enable = true;
      backend = "prison";
      role = "primary";
      freshInit.enable = true;
      zones."example.com".text = ''
        $TTL 3600
        example.com. IN SOA ns1.example.com. hostmaster.example.com. (1 3600 600 86400 60)
        example.com. IN NS ns1.example.com.
        ns1.example.com. IN A 203.0.113.2
      '';
    };
  };
  freshPrison = freshHost.config.services.prisons.knot;
  freshInitializer = lib.findFirst (service: service.name == "initialize") null freshPrison.svcList;
  freshPreparer = lib.findFirst (service: service.name == "prepare") null freshPrison.svcList;

  expandedHost = evalHost {
    services.knotService = {
      enable = true;
      role = "primary";
      freshInit.enable = true;
      zones."example.com".text = ''
        $TTL 3600
        example.com. IN SOA ns.example.com. hostmaster.example.com. (1 3600 600 86400 60)
        example.com. IN NS ns.example.com.
        ns.example.com. IN A 203.0.113.2
      '';
      zones."other.test".text = ''
        $TTL 3600
        other.test. IN SOA ns.other.test. hostmaster.other.test. (1 3600 600 86400 60)
        other.test. IN NS ns.other.test.
        ns.other.test. IN A 203.0.113.10
      '';
    };
  };

  prison = prisonHost.config.services.prisons.knot;
  knotd = builtins.head prison.svcList;

  secondaryHost = evalHost {
    services.knotService = {
      enable = true;
      backend = "nspawn";
      stateVersion = "25.11";
      role = "secondary";
      containerName = "knot-secondary";
      hostAddress = "10.100.1.1";
      localAddress = "10.100.1.2";
      remotes.primary1 = {
        address = [ "198.51.100.1@53" ];
        key = "xfr-primary1";
      };
      primaries.primary1 = {
        address = [ "198.51.100.1@53" ];
        key = "xfr-primary1";
      };
      tsigKeyFiles = [ "/var/lib/secrets/knot-tsig.conf" ];
    };
  };

  nsec3Host = evalHost {
    services.knotService = {
      enable = true;
      backend = "nspawn";
      stateVersion = "25.11";
      hostAddress = "10.100.2.1";
      localAddress = "10.100.2.2";
      dnssec.nsec3 = true;
      zones."example.com".text = ''
        $TTL 3600
        example.com. IN SOA ns1.example.com. hostmaster.example.com. (1 3600 600 86400 60)
        example.com. IN NS ns1.example.com.
        ns1.example.com. IN A 203.0.113.2
      '';
    };
  };

  preflightHost = evalHost {
    services.knotService = {
      enable = true;
      backend = "nspawn";
      stateVersion = "25.11";
      hostAddress = "10.100.5.1";
      localAddress = "10.100.5.2";
      zones."example.com".text = ''
        $TTL 3600
        example.com. IN SOA ns1.example.com. hostmaster.example.com. (1 3600 600 86400 60)
        example.com. IN NS ns1.example.com.
        ns1.example.com. IN A 203.0.113.2
      '';
      remotes.secondary1 = {
        address = [ "198.51.100.2@53" ];
        key = "xfr-secondary1";
      };
      secondaries.secondary1 = {
        address = [ "198.51.100.2@53" ];
        key = "xfr-secondary1";
      };
      tsigKeyFiles = [ "/tmp/knot-tsig-test.conf" ];
    };
  };

  preflightScript = builtins.head preflightHost.config.containers.knot.config.systemd.services.knot.serviceConfig.ExecStartPre;

  innerOf = host: name: host.config.containers.${name}.config;

  # The file Knot actually reads. Producing it runs knotc conf-check, so
  # referencing it at all is the validation.
  configOf = host: name: (innerOf host name).services.knot.settingsFile;

  # Assert against the generated config rather than the attrset behind it, so
  # a rendering bug cannot slip past.
  grepConfig =
    name: pattern: file:
    pkgs.runCommand "check-${name}" { } ''
      if grep -qE ${lib.escapeShellArg pattern} ${file}; then
        echo ok > "$out"
      else
        echo "FAIL: ${name} -- nothing matching ${lib.escapeShellArg pattern}" >&2
        cat ${file} >&2
        exit 1
      fi
    '';

  refuteConfig =
    name: pattern: file:
    pkgs.runCommand "check-${name}" { } ''
      if grep -qE ${lib.escapeShellArg pattern} ${file}; then
        echo "FAIL: ${name} -- unexpected match for ${lib.escapeShellArg pattern}" >&2
        cat ${file} >&2
        exit 1
      fi
      echo ok > "$out"
    '';

  assertEq =
    name: expected: actual:
    pkgs.runCommand "check-${name}" { } (
      if expected == actual then
        "echo ok > $out"
      else
        ''
          echo "FAIL: ${name}" >&2
          echo "  expected: ${lib.escapeShellArg (builtins.toJSON expected)}" >&2
          echo "  actual:   ${lib.escapeShellArg (builtins.toJSON actual)}" >&2
          exit 1
        ''
    );
in
let
  scope = {
    inherit
      pkgs
      lib
      evalHost
      primaryHost
      prisonHost
      freshHost
      freshPrison
      freshInitializer
      freshPreparer
      expandedHost
      prison
      knotd
      secondaryHost
      nsec3Host
      preflightHost
      preflightScript
      innerOf
      configOf
      grepConfig
      refuteConfig
      assertEq
      ;
  };
in
(import ./core-checks.nix scope)
// (import ./prison-checks.nix scope)
// (import ./reconcile-checks.nix scope)
// lib.optionalAttrs (system == "x86_64-linux") {
  prison-setup-to-public-vm = import ./setup-vm.nix { inherit pkgs module; };
  nspawn-public-ipv6-vm = import ./nspawn-network-vm.nix { inherit pkgs module; };
}

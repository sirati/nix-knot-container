{ pkgs, nixpkgs, system, lib, knotZones, module }:

let
  # `boot.isContainer` lets a NixOS system evaluate without a bootloader or
  # filesystems, which is all that is needed to read back generated config.
  evalHost = extra: nixpkgs.lib.nixosSystem {
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
        NS = [ "ns1.example.com." "ns2.example.com." ];
        A = [ "203.0.113.1" ];
        subdomains = {
          ns1.A = [ "203.0.113.2" ];
          ns2.A = [ "203.0.113.3" ];
        };
      };

      remotes.secondary1 = { address = [ "198.51.100.2@53" ]; key = "xfr-secondary1"; };
      secondaries.secondary1 = { address = [ "198.51.100.2@53" ]; key = "xfr-secondary1"; };

      dynamicUpdate.acme = {
        key = "acme-updater";
        allowedTypes = [ "TXT" ];
        allowedOwner = "_acme-challenge.example.com.";
      };

      tsigKeyFiles = [ "/var/lib/secrets/knot-tsig.conf" ];
    };
  };

  secondaryHost = evalHost {
    services.knotService = {
      enable = true;
      stateVersion = "25.11";
      role = "secondary";
      containerName = "knot-secondary";
      hostAddress = "10.100.1.1";
      localAddress = "10.100.1.2";
      remotes.primary1 = { address = [ "198.51.100.1@53" ]; key = "xfr-primary1"; };
      primaries.primary1 = { address = [ "198.51.100.1@53" ]; key = "xfr-primary1"; };
      tsigKeyFiles = [ "/var/lib/secrets/knot-tsig.conf" ];
    };
  };

  nsec3Host = evalHost {
    services.knotService = {
      enable = true;
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

  innerOf = host: name: host.config.containers.${name}.config;

  # The file Knot actually reads. Producing it runs knotc conf-check, so
  # referencing it at all is the validation.
  configOf = host: name: (innerOf host name).services.knot.settingsFile;

  # Assert against the generated config rather than the attrset behind it, so
  # a rendering bug cannot slip past.
  grepConfig = name: pattern: file:
    pkgs.runCommand "check-${name}" { } ''
      if grep -qE ${lib.escapeShellArg pattern} ${file}; then
        echo ok > "$out"
      else
        echo "FAIL: ${name} -- nothing matching ${lib.escapeShellArg pattern}" >&2
        cat ${file} >&2
        exit 1
      fi
    '';

  refuteConfig = name: pattern: file:
    pkgs.runCommand "check-${name}" { } ''
      if grep -qE ${lib.escapeShellArg pattern} ${file}; then
        echo "FAIL: ${name} -- unexpected match for ${lib.escapeShellArg pattern}" >&2
        cat ${file} >&2
        exit 1
      fi
      echo ok > "$out"
    '';

  assertEq = name: expected: actual:
    pkgs.runCommand "check-${name}" { } (
      if expected == actual then "echo ok > $out"
      else ''
        echo "FAIL: ${name}" >&2
        echo "  expected: ${lib.escapeShellArg (builtins.toJSON expected)}" >&2
        echo "  actual:   ${lib.escapeShellArg (builtins.toJSON actual)}" >&2
        exit 1
      ''
    );
in
{
  # Building these runs conf-check. No separate opt-in step exists, and the
  # file Knot reads cannot be produced without the check having passed.
  primary-config-is-valid = configOf primaryHost "knot";
  secondary-config-is-valid = configOf secondaryHost "knot-secondary";

  # DNSSEC has no off switch, so a primary always comes out signing.
  primary-signs = grepConfig "primary-signs" "^ +dnssec-signing: on$"
    (configOf primaryHost "knot");

  primary-uses-signing-policy = grepConfig "primary-uses-signing-policy" "^ +dnssec-policy: signing$"
    (configOf primaryHost "knot");

  # RFC 9276: iterations must be 0 wherever NSEC3 is used.
  nsec3-iterations-are-zero = grepConfig "nsec3-iterations-are-zero" "^ +nsec3-iterations: 0$"
    (configOf nsec3Host "knot");

  # A secondary has no zone file; contents arrive by transfer.
  secondary-loads-no-zonefile = grepConfig "secondary-loads-no-zonefile" "^ +zonefile-load: none$"
    (configOf secondaryHost "knot-secondary");

  # Generated zones let Knot own the serial, and never write back to the store.
  primary-lets-knot-own-serials = grepConfig "primary-lets-knot-own-serials" "^ +zonefile-load: difference-no-serial$"
    (configOf primaryHost "knot");

  primary-never-writes-to-store = grepConfig "primary-never-writes-to-store" "^ +zonefile-sync: -1$"
    (configOf primaryHost "knot");

  # The secrets are included from outside the store, and the placeholder used
  # during the check must not survive into the shipped file.
  config-includes-key-file = grepConfig "config-includes-key-file"
    "^include: /var/lib/secrets/knot-tsig\\.conf$"
    (configOf primaryHost "knot");

  config-has-no-placeholder-secret = refuteConfig "config-has-no-placeholder-secret"
    "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleTEyMz0="
    (configOf primaryHost "knot");

  config-has-no-key-section = refuteConfig "config-has-no-key-section" "^key:$"
    (configOf primaryHost "knot");

  # Dynamic update is bound to a key and narrowed to one type at one owner.
  ddns-acl-is-restricted = grepConfig "ddns-acl-is-restricted" "^ +update-type: \\[ TXT \\]$"
    (configOf primaryHost "knot");

  ddns-acl-is-owner-scoped = grepConfig "ddns-acl-is-owner-scoped"
    "^ +update-owner-name: \\[ _acme-challenge\\.example\\.com\\. \\]$"
    (configOf primaryHost "knot");

  ddns-acl-requires-key = grepConfig "ddns-acl-requires-key" "^ +key: acme-updater$"
    (configOf primaryHost "knot");

  # The container is the security boundary, so it needs its own netns.
  container-has-private-network = assertEq "container-has-private-network" true
    primaryHost.config.containers.knot.privateNetwork;

  firewall-is-dns-only = assertEq "firewall-is-dns-only"
    { tcp = [ 53 ]; udp = [ 53 ]; }
    (let n = (innerOf primaryHost "knot").networking.firewall;
     in { tcp = n.allowedTCPPorts; udp = n.allowedUDPPorts; });

  tsig-keys-are-bind-mounted = assertEq "tsig-keys-are-bind-mounted"
    { hostPath = "/var/lib/secrets/knot-tsig.conf"; isReadOnly = true; }
    (let m = primaryHost.config.containers.knot.bindMounts."/var/lib/secrets/knot-tsig.conf";
     in { inherit (m) hostPath isReadOnly; });

  # A TSIG secret in the store is readable by every user on the machine.
  rejects-tsig-key-in-store = assertEq "rejects-tsig-key-in-store" true
    (let
      bad = evalHost {
        services.knotService = {
          enable = true;
          stateVersion = "25.11";
          hostAddress = "10.100.4.1";
          localAddress = "10.100.4.2";
          zones."example.com".text = ''
            $TTL 3600
            example.com. IN SOA ns1.example.com. hostmaster.example.com. (1 3600 600 86400 60)
            example.com. IN NS ns1.example.com.
            ns1.example.com. IN A 203.0.113.2
          '';
          tsigKeyFiles = [ "${builtins.storeDir}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tsig.conf" ];
        };
      };
    in !(builtins.tryEval bad.config.system.build.toplevel).success);

  # A secondary with no primary would silently serve nothing.
  rejects-secondary-without-primary = assertEq "rejects-secondary-without-primary" true
    (let
      bad = evalHost {
        services.knotService = {
          enable = true;
          stateVersion = "25.11";
          role = "secondary";
          hostAddress = "10.100.3.1";
          localAddress = "10.100.3.2";
        };
      };
    in !(builtins.tryEval bad.config.system.build.toplevel).success);
}

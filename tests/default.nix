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

  innerOf = host: name: host.config.containers.${name}.config;

  settingsOf = host: name: (innerOf host name).services.knot.settings;

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
  # The whole point: the settings this module generates are a config Knot
  # accepts. conf-check resolves every id reference and enforces Knot's
  # pairwise constraints, so this catches far more than a schema would.
  primary-config-is-valid = knotZones.checkConfig {
    name = "knot-primary.conf";
    settings = settingsOf primaryHost "knot";
  };

  secondary-config-is-valid = knotZones.checkConfig {
    name = "knot-secondary.conf";
    settings = settingsOf secondaryHost "knot-secondary";
  };

  # DNSSEC is not an option that can be turned off, so a primary must always
  # come out signing.
  primary-signs = assertEq "primary-signs" true
    (let t = builtins.head (settingsOf primaryHost "knot").template;
     in t.dnssec-signing or false);

  primary-uses-signing-policy = assertEq "primary-uses-signing-policy" "signing"
    (let t = builtins.head (settingsOf primaryHost "knot").template;
     in t.dnssec-policy or null);

  # RFC 9276: NSEC3 iterations must be 0 when NSEC3 is used at all.
  nsec3-iterations-are-zero =
    let
      host = evalHost {
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
      p = builtins.head (settingsOf host "knot").policy;
    in
    assertEq "nsec3-iterations-are-zero" 0 (p.nsec3-iterations or null);

  # A secondary has no zone file to load; contents arrive by transfer.
  secondary-loads-no-zonefile = assertEq "secondary-loads-no-zonefile" "none"
    (let t = builtins.head (settingsOf secondaryHost "knot-secondary").template;
     in t.zonefile-load or null);

  # Dynamic update must be bound to a key and, here, to one type and one owner.
  ddns-acl-is-restricted = assertEq "ddns-acl-is-restricted"
    { id = "ddns-acme"; key = "acme-updater"; action = "update";
      update-type = [ "TXT" ];
      update-owner = "name"; update-owner-match = "equal";
      update-owner-name = [ "_acme-challenge.example.com." ]; }
    (builtins.head (settingsOf primaryHost "knot").acl);

  # The container is the security boundary, so it must have its own netns.
  container-has-private-network = assertEq "container-has-private-network" true
    primaryHost.config.containers.knot.privateNetwork;

  # Only what a nameserver needs.
  firewall-is-dns-only = assertEq "firewall-is-dns-only"
    { tcp = [ 53 ]; udp = [ 53 ]; }
    (let n = (innerOf primaryHost "knot").networking.firewall;
     in { tcp = n.allowedTCPPorts; udp = n.allowedUDPPorts; });

  # TSIG secrets are bind-mounted from outside, never copied into the store.
  tsig-keys-are-bind-mounted = assertEq "tsig-keys-are-bind-mounted"
    { hostPath = "/var/lib/secrets/knot-tsig.conf"; isReadOnly = true; }
    (let m = primaryHost.config.containers.knot.bindMounts."/var/lib/secrets/knot-tsig.conf";
     in { inherit (m) hostPath isReadOnly; });

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

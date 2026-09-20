# Evaluation/build checks split from default.nix to keep each test file focused.
scope: with scope; {
  # Building these runs conf-check. No separate opt-in step exists, and the
  # file Knot reads cannot be produced without the check having passed.
  primary-config-is-valid = configOf primaryHost "knot";
  secondary-config-is-valid = configOf secondaryHost "knot-secondary";

  # DNSSEC has no off switch, so a primary always comes out signing.
  primary-signs = grepConfig "primary-signs" "^ +dnssec-signing: on$" (configOf primaryHost "knot");

  primary-uses-signing-policy =
    grepConfig "primary-uses-signing-policy" "^ +dnssec-policy: signing$"
      (configOf primaryHost "knot");

  # RFC 9276: iterations must be 0 wherever NSEC3 is used.
  nsec3-iterations-are-zero = grepConfig "nsec3-iterations-are-zero" "^ +nsec3-iterations: 0$" (
    configOf nsec3Host "knot"
  );

  # A secondary has no zone file; contents arrive by transfer.
  secondary-loads-no-zonefile = grepConfig "secondary-loads-no-zonefile" "^ +zonefile-load: none$" (
    configOf secondaryHost "knot-secondary"
  );

  # Generated zones let Knot own the serial, and never write back to the store.
  primary-lets-knot-own-serials =
    grepConfig "primary-lets-knot-own-serials" "^ +zonefile-load: difference-no-serial$"
      (configOf primaryHost "knot");

  primary-never-writes-to-store = grepConfig "primary-never-writes-to-store" "^ +zonefile-sync: -1$" (
    configOf primaryHost "knot"
  );

  # The secrets are included from outside the store, and the placeholder used
  # during the check must not survive into the shipped file.
  config-includes-key-file =
    grepConfig "config-includes-key-file" "^include: /var/lib/secrets/knot-tsig\\.conf$"
      (configOf primaryHost "knot");

  config-has-no-placeholder-secret =
    refuteConfig "config-has-no-placeholder-secret" "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleTEyMz0="
      (configOf primaryHost "knot");

  config-has-no-key-section = refuteConfig "config-has-no-key-section" "^key:$" (
    configOf primaryHost "knot"
  );

  # Dynamic update is bound to a key and narrowed to one type at one owner.
  ddns-acl-is-restricted = grepConfig "ddns-acl-is-restricted" "^ +update-type: \\[ TXT \\]$" (
    configOf primaryHost "knot"
  );

  ddns-acl-is-owner-scoped =
    grepConfig "ddns-acl-is-owner-scoped"
      "^ +update-owner-name: \\[ _acme-challenge\\.example\\.com\\. \\]$"
      (configOf primaryHost "knot");

  ddns-acl-requires-key = grepConfig "ddns-acl-requires-key" "^ +key: acme-updater$" (
    configOf primaryHost "knot"
  );

  # The container is the security boundary, so it needs its own netns.
  container-has-private-network =
    assertEq "container-has-private-network" true
      primaryHost.config.containers.knot.privateNetwork;

  firewall-is-dns-only =
    assertEq "firewall-is-dns-only"
      {
        tcp = [ 53 ];
        udp = [ 53 ];
      }
      (
        let
          n = (innerOf primaryHost "knot").networking.firewall;
        in
        {
          tcp = n.allowedTCPPorts;
          udp = n.allowedUDPPorts;
        }
      );

  tsig-keys-are-bind-mounted =
    assertEq "tsig-keys-are-bind-mounted"
      {
        hostPath = "/var/lib/secrets/knot-tsig.conf";
        isReadOnly = true;
      }
      (
        let
          m = primaryHost.config.containers.knot.bindMounts."/var/lib/secrets/knot-tsig.conf";
        in
        {
          inherit (m) hostPath isReadOnly;
        }
      );

  # A TSIG secret in the store is readable by every user on the machine.
  rejects-tsig-key-in-store = assertEq "rejects-tsig-key-in-store" true (
    let
      bad = evalHost {
        services.knotService = {
          enable = true;
          backend = "nspawn";
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
    in
    !(builtins.tryEval bad.config.system.build.toplevel).success
  );

  # A secondary with no primary would silently serve nothing.
  rejects-secondary-without-primary = assertEq "rejects-secondary-without-primary" true (
    let
      bad = evalHost {
        services.knotService = {
          enable = true;
          backend = "nspawn";
          stateVersion = "25.11";
          role = "secondary";
          hostAddress = "10.100.3.1";
          localAddress = "10.100.3.2";
        };
      };
    in
    !(builtins.tryEval bad.config.system.build.toplevel).success
  );

  # --- activation-time checking of secret metadata -----------------------------
  #
  # The build validates everything that does not depend on a secret. These
  # exercise the metadata-only preflight that runs before knotd. It must never
  # open or parse the real key material.

  preflight-accepts-a-good-key =
    pkgs.runCommand "check-preflight-accepts-a-good-key"
      {
        nativeBuildInputs = [
          pkgs.knot-dns
          pkgs.coreutils
        ];
      }
      ''
        mkdir -p /tmp
        { echo "key:"
          echo "  - id: xfr-secondary1"
          echo "    algorithm: hmac-sha256"
          echo "    secret: $(head -c 32 /dev/urandom | base64 -w0)"
        } > /tmp/knot-tsig-test.conf
        chmod 0400 /tmp/knot-tsig-test.conf
        ${preflightScript}
        echo ok > $out
      '';

  preflight-rejects-world-readable-key =
    pkgs.runCommand "check-preflight-rejects-world-readable-key"
      {
        nativeBuildInputs = [
          pkgs.knot-dns
          pkgs.coreutils
        ];
      }
      ''
        mkdir -p /tmp
        { echo "key:"
          echo "  - id: xfr-secondary1"
          echo "    algorithm: hmac-sha256"
          echo "    secret: $(head -c 32 /dev/urandom | base64 -w0)"
        } > /tmp/knot-tsig-test.conf
        chmod 0644 /tmp/knot-tsig-test.conf
        if ${preflightScript} 2>err; then
          echo "FAIL: a world-readable TSIG key was accepted" >&2
          exit 1
        fi
        grep -q 'world-readable' err || { echo "FAIL: wrong reason:" >&2; cat err >&2; exit 1; }
        cat err >&2
        echo ok > $out
      '';

  preflight-rejects-missing-key =
    pkgs.runCommand "check-preflight-rejects-missing-key"
      {
        nativeBuildInputs = [
          pkgs.knot-dns
          pkgs.coreutils
        ];
      }
      ''
        rm -f /tmp/knot-tsig-test.conf
        if ${preflightScript} 2>err; then
          echo "FAIL: a missing TSIG key file was accepted" >&2
          exit 1
        fi
        grep -q 'does not exist' err || { echo "FAIL: wrong reason:" >&2; cat err >&2; exit 1; }
        cat err >&2
        echo ok > $out
      '';

  preflight-does-not-read-key =
    pkgs.runCommand "check-preflight-does-not-read-key" { nativeBuildInputs = [ pkgs.coreutils ]; }
      ''
        mkdir -p /tmp
        printf 'deliberately unreadable and not valid Knot syntax\n' > /tmp/knot-tsig-test.conf
        chmod 0000 /tmp/knot-tsig-test.conf
        ${preflightScript}
        echo ok > $out
      '';

  # The preflight has to actually be wired into the unit, or none of the above
  # runs in production.
  preflight-is-wired-into-the-unit = assertEq "preflight-is-wired-into-the-unit" 1 (
    builtins.length (innerOf primaryHost "knot").systemd.services.knot.serviceConfig.ExecStartPre
  );
}

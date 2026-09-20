# Evaluation/build checks split from default.nix to keep each test file focused.
scope: with scope; {
  # ---- the prison backend --------------------------------------------------

  # The default backend is the locked-down one.
  prison-is-the-default =
    assertEq "prison-is-the-default" "prison"
      (evalHost {
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
        };
      }).config.services.knotService.backend;

  # Binding port 53 is the only privilege knotd is given.
  prison-grants-only-net-bind = assertEq "prison-grants-only-net-bind" [
    "CAP_NET_BIND_SERVICE"
  ] knotd.capabilities;

  prison-root-is-read-only = assertEq "prison-root-is-read-only" true knotd.readOnlyRoot;

  prison-does-not-run-as-root = assertEq "prison-does-not-run-as-root" true (knotd.uid != 0);

  # A TSIG secret is bound one file at a time, read-only, from outside the
  # store -- never copied in and never the whole directory.
  prison-mounts-the-secret-read-only =
    let
      m = lib.findFirst (x: x.path == "/secrets/knot-tsig.conf") null knotd.persist;
    in
    assertEq "prison-mounts-the-secret-read-only"
      {
        host = "/var/lib/secrets/knot-tsig.conf";
        readOnly = true;
        file = true;
      }
      {
        inherit (m) host;
        readOnly = m.readOnly or false;
        file = m.file or false;
      };

  # ...and the configuration includes it at the path it is mounted at.
  prison-config-includes-the-container-path = pkgs.runCommand "check-prison-config-include" { } ''
    grep -qE '^include: /secrets/knot-tsig\.conf$' ${knotd.configTree}/knot.conf
    echo ok > $out
  '';

  # A prison has no `knot` account to drop to and no syslog to write to.
  prison-config-has-no-setuid-or-syslog = pkgs.runCommand "check-prison-config-runtime" { } ''
    if grep -qE '^ +user:' ${knotd.configTree}/knot.conf; then
      echo "FAIL: config tells knotd to setuid inside a container that cannot" >&2
      exit 1
    fi
    grep -qE '^ +- target: stdout$' ${knotd.configTree}/knot.conf
    echo ok > $out
  '';

  # The KASP database holds the DNSSEC private keys, so it has to outlive the
  # container rather than sit on a tmpfs.
  prison-keys-are-persistent =
    let
      m = lib.findFirst (x: x.path == "/var/lib/knot") null knotd.persist;
    in
    assertEq "prison-keys-are-persistent" true (m != null && !(m.readOnly or false));

  # ...and must not land inside the prison's own state directory.
  prison-state-does-not-collide = assertEq "prison-state-does-not-collide" false (
    let
      m = lib.findFirst (x: x.path == "/var/lib/knot") null knotd.persist;
    in
    m.host == prison.stateDir
  );

  prison-listens-on-dns-only = assertEq "prison-listens-on-dns-only" {
    tcp = [ 53 ];
    udp = [ 53 ];
  } { inherit (prison.listen) tcp udp; };

  # Egress is opened to the declared peer and to nothing else, so NOTIFY and
  # transfers work and nothing else leaves.
  prison-egress-is-the-peers-only = assertEq "prison-egress-is-the-peers-only" {
    mode = "targets";
    targets = [
      {
        address = "198.51.100.2";
        port = 53;
        protocol = "udp";
      }
      {
        address = "198.51.100.2";
        port = 53;
        protocol = "tcp";
      }
    ];
  } { inherit (prison.egress) mode targets; };

  prison-ruleset-drops-by-default = pkgs.runCommand "check-prison-ruleset" { } ''
    grep -q 'policy drop' ${prison.ruleset}
    grep -qE 'ip daddr 198\.51\.100\.2 (udp|tcp) dport 53 accept' ${prison.ruleset}
    echo ok > $out
  '';
}

# KSK submission and the prepare unit's recovery, checked against the
# generated configuration and units.
scope:
with scope;
let
  zone = {
    SOA = {
      nameServer = "ns1.example.com.";
      adminEmail = "hostmaster@example.com";
      serial = 1;
    };
    NS = [ "ns1.example.com." ];
    A = [ "203.0.113.1" ];
    subdomains.ns1.A = [ "203.0.113.2" ];
  };

  submissionHost = evalHost {
    services.knotService = {
      enable = true;
      role = "primary";
      zones."example.com".zone = zone;
      dnssec.kskSubmission.parents = [
        "192.0.2.53@53"
        "2001:db8::53@53"
      ];
    };
  };
  submissionPrison = submissionHost.config.services.prisons.knot;
  submissionKnotd = lib.findFirst (s: s.name == "knotd") null submissionPrison.svcList;
  submissionConfig = "${submissionKnotd.configTree}/knot.conf";
in
{
  # The policy names a submission whose parent is one remote holding both
  # addresses. The file exists only if `knotc conf-check` accepted it.
  ksk-submission-is-configured = pkgs.runCommand "check-ksk-submission" { } ''
    conf=${submissionConfig}
    grep -qE '^ *ksk-submission: parent$' "$conf"
    grep -qE '^submission:' "$conf"
    grep -qE 'parent: \[ ksk-submission-parent \]|parent: ksk-submission-parent' "$conf"
    grep -qE 'id: ksk-submission-parent' "$conf"
    grep -qF '192.0.2.53@53' "$conf"
    grep -qF '2001:db8::53@53' "$conf"
    # 0 waits for the DS forever; anything else could finish a rollover the
    # parent never saw.
    grep -qE '^ *timeout: 0$' "$conf"
    echo ok > $out
  '';

  ksk-submission-is-off-by-default = refuteConfig "ksk-submission-is-off-by-default" "ksk-submission|^submission:" "${knotd.configTree}/knot.conf";

  # Knot's prison may reach the submission parents and nothing new besides.
  ksk-submission-opens-egress-to-the-parents =
    assertEq "ksk-submission-opens-egress-to-the-parents"
      [
        {
          address = "192.0.2.53";
          port = 53;
          protocol = "udp";
        }
        {
          address = "192.0.2.53";
          port = 53;
          protocol = "tcp";
        }
        {
          address = "2001:db8::53";
          port = 53;
          protocol = "udp";
        }
        {
          address = "2001:db8::53";
          port = 53;
          protocol = "tcp";
        }
      ]
      submissionPrison.egress.targets;

  # knotd requires prepare. A prepare that gave up on its first failure left
  # the zone unserved; it retries, bounded, and stays activating meanwhile so
  # knotd's start waits for it.
  prepare-retries-before-knotd-gives-up =
    let
      unit = freshHost.config.systemd.services."knot-prepare";
    in
    assertEq "prepare-retries-before-knotd-gives-up"
      {
        restart = "on-failure";
        mode = "direct";
        bounded = true;
        required = true;
      }
      {
        restart = unit.serviceConfig.Restart;
        mode = unit.serviceConfig.RestartMode;
        bounded = unit.startLimitBurst > 1 && unit.startLimitIntervalSec > 0;
        required = builtins.elem "knot-prepare.service" freshHost.config.systemd.services."knot-knotd".requires;
      };

  # Each retry runs the prison's store-view check first, so a prepare that
  # failed against a view left on an older closure gets a fresh view.
  prepare-retries-check-the-store-view =
    let
      cond = lib.concatStringsSep " " (
        map builtins.unsafeDiscardStringContext
          freshHost.config.systemd.services."knot-prepare".serviceConfig.ExecCondition
      );
      farm = builtins.unsafeDiscardStringContext "${freshPreparer.storeFarm}/nix/store";
    in
    assertEq "prepare-retries-check-the-store-view" true (
      lib.hasInfix "/bin/prison-store-check " cond
      && lib.hasInfix "--view knot-store-prepare.service ${farm}" cond
    );
}

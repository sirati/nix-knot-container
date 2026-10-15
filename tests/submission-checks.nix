# KSK submission and the prepare unit's recovery, checked against the
# generated configuration and units.
scope:
with scope;
let
  # The removed option: Knot used to ask these resolvers for the DS itself.
  withParents = evalHost {
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
      };
      dnssec.kskSubmission.parents = [ "192.0.2.53@53" ];
    };
  };
in
{
  # Knot never queries the parent: a KSK waiting for its DS is confirmed
  # from outside the prison with `knotc zone-ksk-submitted`.
  ksk-submission-is-never-configured = refuteConfig "ksk-submission-is-never-configured"
    "ksk-submission|^submission:|ksk-submission-parent" "${knotd.configTree}/knot.conf";

  ksk-submission-parents-are-refused = assertEq "ksk-submission-parents-are-refused" false
    (builtins.tryEval withParents.config.system.build.toplevel).success;

  # A primary with secondaries reaches exactly them, whatever its DNSSEC
  # policy: no recursive resolver a compromised knotd could tunnel through.
  primary-egress-is-the-secondaries-only =
    assertEq "primary-egress-is-the-secondaries-only"
      (lib.concatMap (s: lib.concatMap (a:
        let address = builtins.head (lib.splitString "@" a); in [
          { inherit address; port = 53; protocol = "udp"; }
          { inherit address; port = 53; protocol = "tcp"; }
        ]) s.address) (builtins.attrValues prisonHost.config.services.knotService.secondaries))
      prison.egress.targets;

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

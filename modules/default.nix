# services.knotService: Knot DNS, in a prison by default.

{ lib, ... }:

{
  imports = [
    ./knot.nix
    ./nspawn.nix
    ./prison.nix
    # Knot asked these addresses for the parent's DS, which meant egress from
    # the prison holding the zone keys to recursive resolvers: a tunnel for
    # a compromised knotd. The check now runs outside the prison.
    (lib.mkRemovedOptionModule [ "services" "knotService" "dnssec" "kskSubmission" ] ''
      Knot no longer queries the parent for the DS, and its prison has no
      egress to resolvers. Confirm a KSK submission from outside the prison
      with `knotc zone-ksk-submitted ZONE +ttl DS_TTL` on the control socket,
      once the parent's DS has validated for at least its TTL.
    '')
  ];
}

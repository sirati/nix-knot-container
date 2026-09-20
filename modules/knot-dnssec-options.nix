# DNSSEC policy controls for the Knot service.
{ lib }:

let
  inherit (lib) mkOption types;
in
{
  algorithm = mkOption {
    type = types.enum [
      "ecdsap256sha256"
      "ecdsap384sha384"
      "ed25519"
      "rsasha256"
    ];
    default = "ecdsap256sha256";
    description = ''
      Signing algorithm. ECDSA P-256 is the interoperable default: smaller
      signatures than RSA and universally supported, which ed25519 still
      is not.
    '';
  };
  nsec3 = mkOption {
    type = types.bool;
    default = false;
    description = ''
      Use NSEC3 rather than NSEC. NSEC3 only frustrates casual zone
      enumeration -- it does not prevent it -- and costs every negative
      answer a hash. Enable it if enumeration matters to you; iterations
      are pinned to 0 per RFC 9276 either way.
    '';
  };
  singleType = mkOption {
    type = types.bool;
    default = false;
    description = ''
      Single-type signing: one key acting as both KSK and ZSK. Simpler,
      at the cost of needing a DS update for every rollover.
    '';
  };
  kskLifetime = mkOption {
    type = types.ints.unsigned;
    default = 0;
    description = ''
      KSK lifetime in seconds. 0 means no automatic rollover, which is the
      safe default: a KSK roll needs a matching DS update at the parent,
      and Knot cannot do that for you unless you configure a submission.
    '';
  };
  zskLifetime = mkOption {
    type = types.ints.unsigned;
    default = 2592000;
    description = "ZSK lifetime in seconds. Rolls automatically; no parent involvement needed.";
  };
  propagationDelay = mkOption {
    type = types.ints.unsigned;
    default = 3600;
    description = ''
      Time to assume a zone change needs to reach every secondary before
      the next rollover step. Too low and a rollover can outrun the
      transfers, leaving a resolver holding signatures whose key it cannot
      see. Should exceed your slowest secondary's refresh.
    '';
  };
  signatureLifetime = mkOption {
    type = types.ints.unsigned;
    default = 1209600;
    description = "RRSIG validity in seconds (default 14 days).";
  };
  signatureRefresh = mkOption {
    type = types.ints.unsigned;
    default = 604800;
    description = ''
      Re-sign this long before expiry (default 7 days). The gap between
      this and signatureLifetime is how long the server can be down before
      signatures start expiring and the zone goes dark for validating
      resolvers.
    '';
  };
}

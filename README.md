# knot-service

A NixOS container that runs [Knot DNS](https://www.knot-dns.cz/) and nothing
else. Zone files only, always signed, minimal attack surface.

## Design constraints

**Zone files only.** No SQL backend, no Redis/Valkey zone database. Knot's
`storage` is a read-only Nix store path built by
[knot-zones](https://github.com/sirati/nix-dns-knot); its journal in `/var/lib/knot` is the only
mutable copy. There is never a question about which representation is
authoritative, and there is no database to back up, migrate, or leave running.

**DNSSEC is not optional.** There is deliberately no `dnssec.enable = false`.
An authoritative server serving unsigned zones by default is a downgrade
waiting to happen, and with Knot's automatic key management the cost of signing
is close to zero. You can tune the algorithm and rollover; you cannot turn it
off.

**The container is the boundary.** `privateNetwork = true` gives it its own
network namespace, so the firewall inside it is the whole exposure rather than
a filter layered over the host's interfaces. Ports 53/tcp and 53/udp are open
and nothing else. A nameserver answers queries and talks to its peers; it does
not need outbound anything.

## Usage

```nix
{
  imports = [ knot-service.nixosModules.default ];

  services.knotService = {
    enable = true;
    stateVersion = "25.11";
    role = "primary";

    hostAddress = "10.100.0.1";
    localAddress = "10.100.0.2";

    zones."example.com".zone = {
      SOA = { nameServer = "ns1.example.com."; adminEmail = "hostmaster@example.com"; serial = 1; };
      NS = [ "ns1.example.com." "ns2.example.com." ];
      A = [ "203.0.113.1" ];
    };

    remotes.secondary1    = { address = [ "198.51.100.2@53" ]; key = "xfr-secondary1"; };
    secondaries.secondary1 = { address = [ "198.51.100.2@53" ]; key = "xfr-secondary1"; };

    dynamicUpdate.acme = {
      key = "acme-updater";
      allowedTypes = [ "TXT" ];
      allowedOwner = "_acme-challenge.example.com.";
    };

    tsigKeyFiles = [ "/var/lib/secrets/knot-tsig.conf" ];
  };
}
```

A secondary is the same module with `role = "secondary"` and `primaries` set.
Secondaries load no zone file — `zonefile-load: none` — because contents arrive
by transfer and live in the journal.

## Secrets

TSIG secrets never appear in an option value. `tsigKeyFiles` points at files on
the host holding `key:` sections; they are bind-mounted read-only into the
container and included by Knot at runtime. Anything written into a Nix option
lands in the world-readable store, and a TSIG secret there is a zone-transfer
and dynamic-update credential handed to every local user.

This does mean `knotc conf-check` cannot resolve those key references at build
time. `knot-zones.checkConfig` substitutes placeholder secrets for the check
only, so the structure is validated without the secrets being present — and its
output is a receipt rather than the config file, so nobody deploys the
placeholders by accident.

## Dynamic update

RFC 2136 updates are authorised per key, and narrowed by type and owner:

```nix
dynamicUpdate.acme = {
  key = "acme-updater";
  allowedTypes = [ "TXT" ];
  allowedOwner = "_acme-challenge.example.com.";
};
```

The default `allowedTypes` is `[ "A" "AAAA" "TXT" ]`. Narrowing an ACME key to
`[ "TXT" ]` and one owner means a leaked dns-01 credential can answer challenges
and nothing else — it cannot repoint an A record. An empty list permits every
type, including NS and DNSKEY, which is almost never what you want.

An `update` ACL with no key is rejected by an assertion: authorising by address
alone is forgeable over UDP.

## DNSSEC defaults

| | | |
|---|---|---|
| `algorithm` | `ecdsap256sha256` | Interoperable; smaller than RSA, better supported than ed25519 |
| `nsec3` | `false` | NSEC3 only frustrates casual enumeration and costs a hash per negative answer. Iterations are pinned to 0 per RFC 9276 when enabled |
| `kskLifetime` | `0` (no auto-roll) | A KSK roll needs a DS update at the parent, which Knot cannot do unattended without a configured submission |
| `zskLifetime` | 30 days | Rolls automatically, no parent involvement |
| `propagationDelay` | 1 hour | Must exceed your slowest secondary's refresh, or a rollover can outrun transfers and leave resolvers holding signatures for a key they cannot see |
| `signatureLifetime` | 14 days | |
| `signatureRefresh` | 7 days | The gap between the two is how long the server can be down before signatures expire and the zone goes dark for validating resolvers |

## Hardening

Beyond what nixpkgs' `services.knot` already sets, the unit drops to
`CAP_NET_BIND_SERVICE` alone, with `ProtectSystem=strict`,
`ProtectProc=invisible`, `MemoryDenyWriteExecute`, a `@system-service` syscall
filter minus `@privileged` and `@resources`, and `/var/lib/knot` as the only
writable path. The container itself has no documentation, no default packages,
no polkit, and does not use the host's `resolv.conf` — it is the name service,
so it points at itself.

## Tests

`nix flake check` evaluates both a primary and a secondary, then runs the
generated settings through `knotc conf-check`. It also asserts the properties
that are supposed to be structural: that a primary always signs, that NSEC3
iterations are 0, that a secondary loads no zone file, that the DDNS ACL is
bound to a key and narrowed, that the firewall is DNS-only, that TSIG files are
bind-mounted rather than copied, and that a secondary with no primary fails to
evaluate.

Two bugs were found by `conf-check` while writing this and would not have been
caught by any amount of schema validation: Knot's `log` section is identified by
`target` rather than `id`, and `zonefile-load: difference-no-serial` requires
`journal-content: all`.

## Not yet done

There is no NixOS VM test that boots the container and resolves a query against
it. The checks here validate configuration, not runtime behaviour.

## Licence

MIT.

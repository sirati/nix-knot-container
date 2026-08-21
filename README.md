# knot-service

A NixOS container that runs Knot DNS from zone files only — no SQL, Redis or Valkey backend — always DNSSEC-signed, as primary or secondary, with TSIG-authenticated transfers and scoped RFC 2136 dynamic update.

## Input

```nix
inputs = {
  dns.url = "github:nix-community/dns.nix";
  dns.inputs.nixpkgs.follows = "nixpkgs";
  knot-service.url = "github:sirati/nix-knot-container";
  knot-service.inputs.dns.follows = "dns";
};
```

## Primary

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

    remotes.secondary1     = { address = [ "198.51.100.2@53" "2001:db8::2@53" ]; key = "xfr-secondary1"; };
    secondaries.secondary1 = { address = [ "198.51.100.2@53" "2001:db8::2@53" ]; key = "xfr-secondary1"; };

    dynamicUpdate.acme = {
      key = "acme-updater";
      allowedTypes = [ "TXT" ];
      allowedOwner = "_acme-challenge.example.com.";
    };

    dnssec = {
      algorithm = "ecdsap256sha256";
      nsec3 = false;
      zskLifetime = 2592000;
      propagationDelay = 3600;
      signatureLifetime = 1209600;
      signatureRefresh = 604800;
    };

    tsigKeyFiles = [ "/var/lib/secrets/knot-tsig.conf" ];
  };
}
```

## Secondary

```nix
services.knotService = {
  enable = true;
  stateVersion = "25.11";
  role = "secondary";
  containerName = "knot-secondary";

  hostAddress = "10.100.1.1";
  localAddress = "10.100.1.2";

  remotes.primary1  = { address = [ "198.51.100.1@53" ]; key = "xfr-primary1"; };
  primaries.primary1 = { address = [ "198.51.100.1@53" ]; key = "xfr-primary1"; };

  tsigKeyFiles = [ "/var/lib/secrets/knot-tsig.conf" ];
};
```

## Keys

```
key:
  - id: xfr-secondary1
    algorithm: hmac-sha256
    secret: <base64>
  - id: acme-updater
    algorithm: hmac-sha256
    secret: <base64>
```

## Emits

```
include: /var/lib/secrets/knot-tsig.conf

server:
    automatic-acl: on
    listen: [ 0.0.0.0@53, "::@53" ]
    rundir: "/run/knot"
    user: knot:knot

database:
    journal-db: "/var/lib/knot/journal"
    kasp-db: "/var/lib/knot/keys"
    storage: "/var/lib/knot"
    timer-db: "/var/lib/knot/timers"

remote:
  - id: secondary1
    address: [ 198.51.100.2@53 ]
    key: xfr-secondary1

acl:
  - id: ddns-acme
    action: update
    key: acme-updater
    update-owner: name
    update-owner-match: equal
    update-owner-name: [ _acme-challenge.example.com. ]
    update-type: [ TXT ]

policy:
  - id: signing
    algorithm: ecdsap256sha256
    ksk-lifetime: 0
    nsec3: off
    propagation-delay: 3600
    rrsig-lifetime: 1209600
    rrsig-refresh: 604800
    zsk-lifetime: 2592000

template:
  - id: default
    acl: [ ddns-acme ]
    dnssec-policy: signing
    dnssec-signing: on
    journal-content: all
    notify: [ secondary1 ]
    storage: "/nix/store/...-knot-zones"
    zonefile-load: difference-no-serial
    zonefile-sync: -1

zone:
  - domain: example.com.
    template: default
```

## Lockdown

Network:

- `privateNetwork = true` — the container gets its own network namespace, so the firewall below is its entire exposure rather than a filter layered over the host's interfaces.
- Firewall enabled inside the container; `allowedTCPPorts = [ 53 ]` and `allowedUDPPorts = [ 53 ]`, plus 853 only when `enableDoT` / `enableQuic` are set.
- `logRefusedConnections = true` — an unexpected outbound attempt is visible rather than silent.
- `useHostResolvConf = false` and `nameservers = [ "127.0.0.1" ]` — it is the name service, so it resolves against itself and depends on nothing outside.

Privileges:

- `CapabilityBoundingSet` and `AmbientCapabilities` forced to `CAP_NET_BIND_SERVICE` alone — enough to bind port 53, nothing else.
- `NoNewPrivileges`, `RestrictSUIDSGID`, `LockPersonality`, `RestrictRealtime`, `RestrictNamespaces`.
- `SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ]`, `SystemCallArchitectures = "native"`.
- `MemoryDenyWriteExecute` — no W^X pages for a compromised parser to use.
- `RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ]`.

Filesystem:

- `ProtectSystem = "strict"` with `ReadWritePaths = [ "/var/lib/knot" ]` — the journal, KASP database and keys are the only writable state.
- `StateDirectory = "knot"` at mode `0700`, `UMask = "0077"`.
- `ProtectHome`, `PrivateTmp`, `PrivateDevices`.
- `ProtectProc = "invisible"` and `ProcSubset = "pid"` — no visibility of other processes.
- `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`.
- Zone storage is a read-only Nix store path; `zonefile-sync = -1` means Knot never attempts to write back to it.

Secrets:

- `tsigKeyFiles` is `types.listOf types.str`, deliberately not `types.path`. A bare path literal is copied into `/nix/store` with mode `0444` the moment it is interpolated, and nixpkgs' own `services.knot` builds its config with `"include: ${file}"` — so the option that exists to keep TSIG secrets out of the store will put one there if you omit the quotes. A string cannot be copied.
- An assertion rejects any `tsigKeyFiles` entry under `builtins.storeDir`, and `knot-zones` throws on one as well, so a secret that reached the store by any route fails the build rather than shipping.
- The files are bind-mounted read-only into the container and referenced from the config by path; they are never read at evaluation time.
- DNSSEC private keys never come from Nix at all. Knot generates the KSK and ZSK itself into the KASP database at `/var/lib/knot/keys` on first sign, so there is no option through which one could be passed in.
- The config is conf-checked with placeholder `key:` sections standing in for the real ones, and the shipped file contains neither the placeholders nor any `key:` section — only the `include:` line.
- An assertion rejects a secondary with no TSIG key: transfers authorised by address alone are forgeable, and an unauthenticated AXFR hands over the whole zone.
- An assertion rejects `dynamicUpdate` without `tsigKeyFiles`.

Dynamic update:

- Every update ACL is bound to a TSIG key; there is no address-only path.
- `allowedTypes` defaults to `[ "A" "AAAA" "TXT" ]` and narrows further, so an ACME key restricted to `TXT` at one owner cannot repoint an A record.
- `allowedOwner` pins updates to a single exact name.

Surface removed:

- `environment.defaultPackages` forced empty, `documentation` (nixos + man) disabled, `programs.command-not-found` disabled.
- `security.polkit`, `services.udisks2`, `fonts.fontconfig`, `boot.enableContainers` and all `xdg.*` disabled.

DNSSEC:

- No `dnssec.enable = false` exists. Algorithm and rollover are tunable; unsigned is not reachable.
- `nsec3-iterations` pinned to 0 per RFC 9276 whenever NSEC3 is used.
- `kskLifetime` defaults to 0, no automatic KSK rollover, because rolling one needs a DS update at the parent that Knot cannot perform unattended.

## Checks

```console
$ nix flake check
```

## Licence

MIT

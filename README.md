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

- TSIG secrets are never option values. `tsigKeyFiles` are bind-mounted read-only into the container and included by Knot at runtime, because anything in a Nix option lands in the world-readable store, where a TSIG secret is a zone-transfer and dynamic-update credential for every local user.
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

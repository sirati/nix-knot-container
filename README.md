# knot-service

Knot DNS from zone files only — no SQL, Redis or Valkey backend — always DNSSEC-signed, as primary or secondary, with TSIG-authenticated transfers and scoped RFC 2136 dynamic update.

Runs in a [prison](https://github.com/sirati/NixOS-Container-Podman) by
default: a podman container with no shell, no coreutils, no package manager and
no init of its own, holding one capability (`CAP_NET_BIND_SERVICE`) and a
default-drop firewall. `backend = "nspawn"` selects a full NixOS container
instead.

When `services.knotService.enable` is true, the read-only
`services.knotService.generatedConfigFile` option gives the store path of the
validated configuration passed to Knot. The read-only
`services.knotService.generatedZoneStorage` list contains the generated storage
directory and the zone-file outputs behind its links. Both options are empty
when Knot is disabled. `services.knotService.generatedZoneFiles` gives the
regular zone files individually, which is useful for per-file snapshots. These
options expose no TSIG secret contents.

For a prison primary that accepts dynamic updates, set
`services.knotService.freshInit.enable = true`. This adds a manual
`<containerName>-setup.service` unit. Run it only for an empty state directory,
after runtime TSIG secrets are available. It loads generated zones using a
loopback-only Knot daemon, creates DNSSEC keys, and writes a manifest of the
declarative zone records. The unit rejects an existing state directory.

The regular `<containerName>-knotd.service` requires a separate
`<containerName>-prepare.service`. Before Knot starts on its public listener,
prepare compares the previous manifest with the current generated zone files
and applies only changed declarative records through Knot's control API. Knot
loads the journal on restart, retaining records added through RFC 2136. Back
up the whole state directory, including `declarative-zones`, and restore it
before starting the regular service on a replacement host. A service manager
that gates the regular daemon for setup or recovery must gate prepare too.
When a new zone is declared later, prepare initializes only that zone and
retains the existing zones' keys and journal. A missing manifest for a zone
that already has DNSSEC keys is treated as damaged state, not a new zone.
For these units, Knot's PID and control socket live in the private `/run/knot`
tmpfs even if an older configuration set `server.rundir` under persistent
storage. The journal, timers, DNSSEC keys, and zone manifests remain persistent.

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
    role = "primary";
    freshInit.enable = true;

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
  role = "secondary";
  containerName = "knot-secondary";

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

## Validation

Split in two, because a secret must never be in the store and therefore can never be seen by a build.

At build time, everything that does not depend on a secret. Zones go through `kzonecheck`; the configuration goes through `knotc conf-check` with placeholder `key:` sections standing in for the real ones. `services.knot.settingsFile` is the output of that derivation, so the file Knot reads cannot exist unless the check passed, and nothing has to opt in.

At start time, an `ExecStartPre` verifies only secret-file metadata: each key
file must exist, be a regular file, remain outside `/nix/store`, and not be
world-readable. It deliberately does not open or parse the secret. The
generated configuration was already checked with placeholder keys during the
build; `knotd` is the only process that reads the real material.

```
knot-service: TSIG key file /var/lib/secrets/knot-tsig.conf is world-readable (mode 644). Remove world access and grant read access only to knotd.
```

```
knot-service: TSIG key file /var/lib/secrets/knot-tsig.conf does not exist. It is deployed outside Nix, so nothing in the build could have caught this.
```

An absent, misplaced, or world-readable secret fails with a named cause.
Malformed or unreadable key material is rejected by `knotd` itself.

## Lockdown

In the prison backend the container itself is the boundary:

| | |
|---|---|
| capabilities | `CAP_NET_BIND_SERVICE` and nothing else |
| root filesystem | read-only; no shell, no coreutils, no package manager |
| network | its own namespace, default-drop in and out |
| inbound | 53/tcp and 53/udp only (853 with DoT/QUIC) |
| outbound | the declared remotes on their DNS port, nothing else |
| writable | `/var/lib/knot` and a tmpfs rundir, both `noexec,nosuid,nodev` |
| store | knotd's own closure, served read-only through a symlink farm |
| secrets | each TSIG key file bound in read-only, one file at a time |

The `nspawn` backend is a full NixOS container. What it does instead:

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
- `allowedOwner` pins updates to a name. Set `allowedOwnerMatch = "sub"` to
  permit only names below that owner, for example an application's dedicated
  subdomain.

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

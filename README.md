# knot-service

Knot DNS that serves zone files only, with no SQL, Redis or Valkey backend. Zones are always DNSSEC-signed. Knot runs as primary or secondary, with TSIG-authenticated transfers and RFC 2136 dynamic updates limited to declared types and names.

By default it runs in a [prison](https://github.com/sirati/NixOS-Container-Podman).
That is a podman container with no shell, no coreutils, no package manager and
no init of its own. It has one capability (`CAP_NET_BIND_SERVICE`) and a
firewall that drops by default. `backend = "nspawn"` selects a full NixOS
container instead.

When `services.knotService.enable` is true, the read-only
`services.knotService.generatedConfigFile` option gives the store path of the
validated configuration that Knot receives. The read-only
`services.knotService.generatedZoneStorage` list contains the generated storage
directory and the zone-file outputs its links point to. Both options are empty
when Knot is disabled. `services.knotService.generatedZoneFiles` lists the
regular zone files one by one, for example for per-file snapshots. These
options do not contain any TSIG secret.

For a prison primary that accepts dynamic updates, set
`services.knotService.freshInit.enable = true`. This adds a manual
`<containerName>-setup.service` unit. Run it only on an empty state directory,
after the runtime TSIG secrets are in place. It loads the generated zones into
a Knot daemon that listens on loopback only, creates DNSSEC keys, and writes a
manifest of the declarative zone records. The unit refuses to run on an
existing state directory.

The regular `<containerName>-knotd.service` requires a separate
`<containerName>-prepare.service`. Before Knot starts on its public listener,
the prepare unit compares the previous manifest with the current generated
zone files. It applies only the changed declarative records through Knot's
control API. On restart Knot loads the journal, so records added through
RFC 2136 stay. Back up the whole state directory, including
`declarative-zones`. On a replacement host, restore it before you start the
regular service. If a service manager holds back the regular daemon during
setup or recovery, it must hold back the prepare unit too. When you declare a
new zone later, the prepare unit initializes only that zone and keeps the keys
and journal of the existing zones. If a zone already has DNSSEC keys but no
manifest, the prepare unit treats the state as damaged and does not treat it
as a new zone. For these units, Knot's PID file and control socket are in the
private `/run/knot` tmpfs, even if an older configuration set `server.rundir`
to persistent storage. The journal, timers, DNSSEC keys and zone manifests
stay on persistent storage.

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

Validation has two stages. Secrets must never be in the store, so the build can never see them.

At build time, the build checks everything that does not depend on a secret. `kzonecheck` checks the zones. `knotc conf-check` checks the configuration, with placeholder `key:` sections in place of the real ones. `services.knot.settingsFile` is the output of that derivation, so the file Knot reads exists only if the check passed. No module has to opt in.

At start time, an `ExecStartPre` checks only the metadata of the secret files.
Each key file must exist, be a regular file, be outside `/nix/store`, and not
be world-readable. It does not open or parse the secret. The build already
checked the generated configuration with placeholder keys, and `knotd` is the
only process that reads the real keys.

```
knot-service: TSIG key file /var/lib/secrets/knot-tsig.conf is world-readable (mode 644). Remove world access and grant read access only to knotd.
```

```
knot-service: TSIG key file /var/lib/secrets/knot-tsig.conf does not exist. It is deployed outside Nix, so nothing in the build could have caught this.
```

A missing, misplaced or world-readable secret fails with an error that names
the cause. `knotd` itself rejects malformed or unreadable keys.

## Lockdown

In the prison backend, the container itself is the security boundary:

| | |
|---|---|
| capabilities | only `CAP_NET_BIND_SERVICE` |
| root filesystem | read-only; no shell, no coreutils, no package manager |
| network | its own namespace, drops all inbound and outbound traffic by default |
| inbound | only 53/tcp and 53/udp, plus 853 with DoT/QUIC |
| outbound | only the declared remotes, on their DNS port |
| writable | `/var/lib/knot` and a tmpfs rundir, both `noexec,nosuid,nodev` |
| store | only knotd's own closure, mounted read-only through a symlink farm |
| secrets | each TSIG key file bind-mounted read-only, one file at a time |

The `nspawn` backend is a full NixOS container. It uses these settings:

Network:

- `privateNetwork = true` gives the container its own network namespace. The firewall below therefore controls all of its traffic, and does not sit on top of the host's interfaces.
- The firewall is enabled inside the container, with `allowedTCPPorts = [ 53 ]` and `allowedUDPPorts = [ 53 ]`. Port 853 opens only when `enableDoT` or `enableQuic` is set.
- `logRefusedConnections = true` logs unexpected outbound attempts.
- `useHostResolvConf = false` and `nameservers = [ "127.0.0.1" ]`. The container is the name server, so it resolves names against itself and depends on no outside resolver.

Privileges:

- `CapabilityBoundingSet` and `AmbientCapabilities` are forced to `CAP_NET_BIND_SERVICE` alone, which is enough to bind port 53.
- `NoNewPrivileges`, `RestrictSUIDSGID`, `LockPersonality`, `RestrictRealtime`, `RestrictNamespaces`.
- `SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ]`, `SystemCallArchitectures = "native"`.
- `MemoryDenyWriteExecute` denies pages that are both writable and executable, so a compromised parser cannot use them.
- `RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ]`.

Filesystem:

- `ProtectSystem = "strict"` with `ReadWritePaths = [ "/var/lib/knot" ]`. The journal, KASP database and keys are the only writable state.
- `StateDirectory = "knot"` at mode `0700`, `UMask = "0077"`.
- `ProtectHome`, `PrivateTmp`, `PrivateDevices`.
- `ProtectProc = "invisible"` and `ProcSubset = "pid"` hide other processes.
- `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`.
- Zone storage is a read-only Nix store path. With `zonefile-sync = -1`, Knot never tries to write back to it.

Secrets:

- `tsigKeyFiles` has type `types.listOf types.str` on purpose, and does not use `types.path`. Nix copies a bare path literal into `/nix/store` with mode `0444` as soon as it is interpolated. nixpkgs' own `services.knot` builds its config with `"include: ${file}"`. If you leave out the quotes, the option meant to keep TSIG secrets out of the store puts one there. Nix does not copy a string.
- An assertion rejects any `tsigKeyFiles` entry under `builtins.storeDir`, and `knot-zones` throws on one as well. A secret that reached the store by any route fails the build and does not ship.
- The files are bind-mounted read-only into the container, and the config refers to them by path. Nix never reads them at evaluation time.
- DNSSEC private keys never come from Nix. On first signing, Knot generates the KSK and ZSK itself into the KASP database at `/var/lib/knot/keys`. No option exists to pass one in.
- The config is checked with `conf-check` using placeholder `key:` sections in place of the real ones. The shipped file contains no placeholders and no `key:` section. It contains only the `include:` line.
- An assertion rejects a secondary with no TSIG key. An attacker can forge transfers that are authorised by address alone, and an unauthenticated AXFR hands over the whole zone.
- An assertion rejects `dynamicUpdate` without `tsigKeyFiles`.

Dynamic update:

- Every update ACL requires a TSIG key. No ACL allows updates by address alone.
- `allowedTypes` defaults to `[ "A" "AAAA" "TXT" ]` and you can narrow it further. An ACME key limited to `TXT` at one owner cannot change an A record.
- `allowedOwner` limits updates to one name. Set `allowedOwnerMatch = "sub"` to
  permit only names below that owner, for example an application's dedicated
  subdomain.

Removed packages and services:

- `environment.defaultPackages` is forced empty, `documentation` (nixos + man) is disabled, and `programs.command-not-found` is disabled.
- `security.polkit`, `services.udisks2`, `fonts.fontconfig`, `boot.enableContainers` and all `xdg.*` are disabled.

DNSSEC:

- There is no `dnssec.enable = false`. You can tune the algorithm and rollover, and no setting produces unsigned zones.
- `nsec3-iterations` is pinned to 0 per RFC 9276 whenever NSEC3 is used.
- `kskLifetime` defaults to 0, which means no automatic KSK rollover. Rolling a KSK needs a DS update at the parent, and Knot cannot do that unattended.

## Checks

```console
$ nix flake check
```

## Licence

MIT

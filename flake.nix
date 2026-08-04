{
  description = "A locked-down NixOS container running Knot DNS from zone files, always signed";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    dns.url = "github:nix-community/dns.nix";
    # dns.nix pins nixpkgs from 2021, but its own zone.nix calls lib.trim,
    # which nixpkgs only grew in 2024 -- so it does not evaluate against its
    # own lock. Consumers have to supply a newer lib.
    dns.inputs.nixpkgs.follows = "nixpkgs";
    # Absolute, because a relative `path:../knot-zones` is resolved against the
    # store copy of this flake once it is fetched, where the sibling does not
    # exist. Repoint this at a URL when the repos are published, or override it
    # with `--override-input knot-zones <path>`.
    knot-zones.url = "github:sirati/nix-dns-knot";
    knot-zones.inputs.nixpkgs.follows = "nixpkgs";
    knot-zones.inputs.dns.follows = "dns";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, dns, knot-zones, flake-utils }:
    {
      nixosModules.default = { pkgs, lib, ... }: {
        imports = [ ./modules/container.nix ];
        # mkDefault so a consumer with their own knot-zones checkout can
        # override it without forking this module.
        _module.args.knotZones =
          lib.mkDefault knot-zones.lib.${pkgs.stdenv.hostPlatform.system};
      };

      nixosModules.knotService = self.nixosModules.default;
    }
    // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        checks = import ./tests {
          inherit pkgs nixpkgs system;
          lib = nixpkgs.lib;
          knotZones = knot-zones.lib.${system};
          module = self.nixosModules.default;
        };

        devShells.default = pkgs.mkShell {
          packages = [ pkgs.knot-dns pkgs.nixpkgs-fmt ];
        };
      });
}

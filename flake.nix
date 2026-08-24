{
  description = "A locked-down NixOS container running Knot DNS from zone files, always signed";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    dns.url = "github:nix-community/dns.nix";
    # dns.nix pins nixpkgs from 2021, but its own zone.nix calls lib.trim,
    # which nixpkgs only grew in 2024 -- so it does not evaluate against its
    # own lock. Consumers have to supply a newer lib.
    dns.inputs.nixpkgs.follows = "nixpkgs";
    # Override with `--override-input knot-zones <path>` to build against a
    # local checkout.
    knot-zones.url = "github:sirati/nix-dns-knot";
    knot-zones.inputs.nixpkgs.follows = "nixpkgs";
    knot-zones.inputs.dns.follows = "dns";
    # The prison primitive and its NixOS module.
    containers.url = "github:sirati/NixOS-Container-Podman";
    containers.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, dns, knot-zones, containers, flake-utils }:
    {
      nixosModules.default = { pkgs, lib, ... }: {
        imports = [ ./modules containers.nixosModules.prisons ];
        # mkDefault so a consumer with their own checkout can override either
        # without forking this module.
        _module.args.knotZones =
          lib.mkDefault knot-zones.lib.${pkgs.stdenv.hostPlatform.system};
        _module.args.prison =
          lib.mkDefault containers.lib.${pkgs.stdenv.hostPlatform.system};
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

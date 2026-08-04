{
  description = "A locked-down NixOS container running Knot DNS from zone files, always signed";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    dns.url = "github:nix-community/dns.nix";
    knot-zones.url = "path:../knot-zones";
    knot-zones.inputs.nixpkgs.follows = "nixpkgs";
    knot-zones.inputs.dns.follows = "dns";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, dns, knot-zones, flake-utils }:
    {
      nixosModules.default = { pkgs, ... }: {
        imports = [ ./modules/container.nix ];
        _module.args.knotZones = knot-zones.lib.${pkgs.stdenv.hostPlatform.system};
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

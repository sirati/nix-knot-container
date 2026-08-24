# services.knotService: Knot DNS, in a prison by default.

{ ... }:

{
  imports = [
    ./knot.nix
    ./nspawn.nix
    ./prison.nix
  ];
}

{ pkgs, module }:

pkgs.testers.runNixOSTest {
  name = "knot-nspawn-public-ipv6";
  nodes.machine = { ... }: {
    imports = [ module ];
    virtualisation.vlans = [ 1 ];
    networking.interfaces.eth1.ipv6.addresses = [
      { address = "fd00::2"; prefixLength = 64; }
    ];
    services.knotService = {
      enable = true;
      backend = "nspawn";
      stateVersion = "26.05";
      role = "primary";
      containerName = "knot-test";
      hostAddress6 = "fd42:53::1";
      localAddress6 = "fd42:53::2";
      zones."example.test".text = ''
        $TTL 300
        example.test. IN SOA ns.example.test. hostmaster.example.test. (1 3600 600 86400 60)
        example.test. IN NS ns.example.test.
        ns.example.test. IN A 192.0.2.53
      '';
    };
    containers.knot-test.forwardPorts = [
      { protocol = "tcp"; hostPort = 53; }
      { protocol = "udp"; hostPort = 53; }
    ];
    networking.firewall.allowedTCPPorts = [ 53 ];
    networking.firewall.allowedUDPPorts = [ 53 ];
    environment.systemPackages = [ pkgs.knot-dns ];
    virtualisation.memorySize = 2048;
    system.stateVersion = "26.05";
  };
  testScript = ''
    machine.start(allow_reboot=True)
    machine.wait_for_unit("container@knot-test.service")
    machine.wait_until_succeeds(
      "kdig +timeout=2 +retry=0 @fd00::2 example.test. SOA +short | grep -q ns.example.test",
      timeout=90,
    )
    machine.wait_until_succeeds(
      "kdig +tcp +timeout=2 +retry=0 @fd00::2 example.test. SOA +short | grep -q ns.example.test",
      timeout=90,
    )
    machine.reboot()
    machine.wait_for_unit("container@knot-test.service")
    machine.wait_until_succeeds(
      "kdig +tcp +timeout=2 +retry=0 @fd00::2 example.test. SOA +short | grep -q ns.example.test",
      timeout=90,
    )
  '';
}

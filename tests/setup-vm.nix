{ pkgs, module }:

pkgs.testers.runNixOSTest {
  name = "knot-prison-setup-to-public";
  nodes.machine = { lib, pkgs, ... }: {
    imports = [ module ];
    services.knotService = {
      enable = true;
      role = "primary";
      containerName = "knot-test";
      stateDir = "/var/lib/knot-test-state";
      freshInit.enable = true;
      zones."example.test".text = ''
        $TTL 300
        example.test. IN SOA ns.example.test. hostmaster.example.test. (1 3600 600 86400 60)
        example.test. IN NS ns.example.test.
        ns.example.test. IN A 192.0.2.53
      '';
    };
    systemd.services."knot-test-knotd".wantedBy = lib.mkForce [ ];
    systemd.services.knot-test-state = {
      requiredBy = [ "knot-test.service" ];
      before = [ "knot-test.service" ];
      serviceConfig.Type = "oneshot";
      script = ''
        subuid="$(${pkgs.gawk}/bin/awk -F: '$1 == "knot-test" { print $2; exit }' /etc/subuid)"
        test -n "$subuid"
        mapped_uid="$((subuid + 999))"
        install -d -m 0700 -o "$mapped_uid" -g "$mapped_uid" /var/lib/knot-test-state
      '';
    };
    environment.systemPackages = [ pkgs.knot-dns ];
    virtualisation.memorySize = 2048;
    system.stateVersion = "26.05";
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("systemctl start knot-test.service")
    machine.succeed("systemctl start knot-test-setup.service")
    machine.succeed("test -s /var/lib/knot-test-state/journal/data.mdb")
    machine.succeed("test -s /var/lib/knot-test-state/keys/data.mdb")
    machine.succeed("test -s /var/lib/knot-test-state/declarative-zones/example.test.zone")
    machine.succeed("systemctl start knot-test-knotd.service")
    machine.wait_for_unit("knot-test-knotd.service")
    machine.wait_until_succeeds(
      "kdig +timeout=1 +retry=0 @127.0.0.1 example.test. DNSKEY +short | grep -q .",
      timeout=30,
    )
    machine.succeed("test \"$(systemctl show -P Result knot-test-initialize.service)\" = success")
    machine.succeed("test \"$(systemctl show -P Result knot-test-prepare.service)\" = success")
  '';
}

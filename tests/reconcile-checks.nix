scope: with scope; {
  bootstrap-config-is-zone-specific =
    let
      expanded = expandedHost.config.services.prisons.knot;
      preparer = lib.findFirst (service: service.name == "prepare") null expanded.svcList;
      zoneArgs = lib.filter (arg: lib.hasPrefix "example.com.=" arg || lib.hasPrefix "other.test.=" arg) preparer.argv;
      configs = map (arg: builtins.elemAt (lib.splitString "=" arg) 2) zoneArgs;
    in
    pkgs.runCommand "check-knot-zone-bootstrap-configs" { } ''
      test ${toString (builtins.length configs)} -eq 2
      grep -q '^  - domain: example.com.' ${builtins.elemAt configs 0}
      ! grep -q '^  - domain: other.test.' ${builtins.elemAt configs 0}
      grep -q '^  - domain: other.test.' ${builtins.elemAt configs 1}
      ! grep -q '^  - domain: example.com.' ${builtins.elemAt configs 1}
      echo ok > "$out"
    '';

  preserves-ddns-and-applies-static-change = pkgs.runCommand "check-knot-journal-reconciliation" {
    nativeBuildInputs = [ pkgs.coreutils pkgs.gnused pkgs.gnugrep ];
  } ''
    set -eu
    mkdir -p "$TMPDIR/state" "$TMPDIR/run" "$TMPDIR/zones"
    cp ${builtins.head freshHost.config.services.knotService.generatedZoneFiles} \
      "$TMPDIR/zones/example.com.zone"
    chmod 0644 "$TMPDIR/zones/example.com.zone"
    make_config() {
      sed -e "s|/var/lib/knot|$TMPDIR/state|g" \
          -e "s|/run/knot|$TMPDIR/run|g" \
          -e "s|${builtins.head freshHost.config.services.knotService.generatedZoneStorage}|$TMPDIR/zones|g" \
          "$1" > "$2"
    }
    make_config ${freshInitializer.config."knot.conf"} "$TMPDIR/setup.conf"
    make_config ${freshPreparer.config."knot.conf"} "$TMPDIR/prepare.conf"
    make_config ${freshHost.config.services.knotService.generatedConfigFile} "$TMPDIR/normal.conf"
    sed -i 's/0.0.0.0@53/127.0.0.1@1053/g' "$TMPDIR/normal.conf"
    sed -i 's/::@53/::1@1053/g' "$TMPDIR/normal.conf"

    helper=${builtins.head freshInitializer.argv}
    knotd=${pkgs.knot-dns}/bin/knotd
    knotc=${pkgs.knot-dns}/bin/knotc
    keymgr=${pkgs.knot-dns}/bin/keymgr
    kzonecheck=${pkgs.knot-dns}/bin/kzonecheck
    zone=example.com.=$TMPDIR/zones/example.com.zone=$TMPDIR/setup.conf
    "$helper" initialize "$knotd" "$knotc" "$keymgr" "$kzonecheck" \
      "$TMPDIR/setup.conf" "$TMPDIR/state" split "$zone"

    "$knotd" --config "$TMPDIR/normal.conf" &
    daemon=$!
    trap 'kill "$daemon" 2>/dev/null || true' EXIT
    for i in $(seq 1 100); do
      "$knotc" --config "$TMPDIR/normal.conf" status >/dev/null 2>&1 && break
      sleep 0.1
    done
    "$knotc" --config "$TMPDIR/normal.conf" zone-begin example.com.
    "$knotc" --config "$TMPDIR/normal.conf" zone-set example.com. dynamic.example.com. 300 A 192.0.2.44
    "$knotc" --config "$TMPDIR/normal.conf" zone-commit example.com.
    "$knotc" --config "$TMPDIR/normal.conf" zone-read example.com. dynamic.example.com. A \
      | grep -F 192.0.2.44
    "$knotc" --config "$TMPDIR/normal.conf" stop
    wait "$daemon"

    "$knotd" --config "$TMPDIR/normal.conf" &
    daemon=$!
    for i in $(seq 1 100); do
      "$knotc" --config "$TMPDIR/normal.conf" status >/dev/null 2>&1 && break
      sleep 0.1
    done
    "$knotc" --config "$TMPDIR/normal.conf" zone-read example.com. dynamic.example.com. A \
      | grep -F 192.0.2.44
    "$knotc" --config "$TMPDIR/normal.conf" stop
    wait "$daemon"

    printf '\nstatic2.example.com. 300 IN A 203.0.113.8\n' \
      >> "$TMPDIR/zones/example.com.zone"
    "$helper" reconcile "$knotd" "$knotc" "$keymgr" "$kzonecheck" \
      "$TMPDIR/prepare.conf" "$TMPDIR/state" split "$zone"
    "$knotd" --config "$TMPDIR/normal.conf" &
    daemon=$!
    for i in $(seq 1 100); do
      "$knotc" --config "$TMPDIR/normal.conf" status >/dev/null 2>&1 && break
      sleep 0.1
    done
    "$knotc" --config "$TMPDIR/normal.conf" zone-read example.com. dynamic.example.com. A \
      | grep -F 192.0.2.44
    "$knotc" --config "$TMPDIR/normal.conf" zone-read example.com. static2.example.com. A \
      | grep -F 203.0.113.8
    "$knotc" --config "$TMPDIR/normal.conf" stop
    wait "$daemon"

    sed -i '/static2.example.com. 300 IN A 203.0.113.8/d' "$TMPDIR/zones/example.com.zone"
    sed -i 's/203.0.113.2/203.0.113.9/' "$TMPDIR/zones/example.com.zone"
    "$helper" reconcile "$knotd" "$knotc" "$keymgr" "$kzonecheck" \
      "$TMPDIR/prepare.conf" "$TMPDIR/state" split "$zone"
    "$helper" reconcile "$knotd" "$knotc" "$keymgr" "$kzonecheck" \
      "$TMPDIR/prepare.conf" "$TMPDIR/state" split "$zone"
    "$knotd" --config "$TMPDIR/normal.conf" &
    daemon=$!
    for i in $(seq 1 100); do
      "$knotc" --config "$TMPDIR/normal.conf" status >/dev/null 2>&1 && break
      sleep 0.1
    done
    "$knotc" --config "$TMPDIR/normal.conf" zone-read example.com. dynamic.example.com. A \
      | grep -F 192.0.2.44
    "$knotc" --config "$TMPDIR/normal.conf" zone-read example.com. ns1.example.com. A \
      | grep -F 203.0.113.9
    if "$knotc" --config "$TMPDIR/normal.conf" zone-read example.com. static2.example.com. A \
      | grep -F 203.0.113.8; then
      echo "removed declarative record is still present" >&2
      exit 1
    fi
    "$knotc" --config "$TMPDIR/normal.conf" stop
    wait "$daemon"

    existing_keys=$("$keymgr" --config "$TMPDIR/setup.conf" example.com. list)
    mv "$TMPDIR/state/declarative-zones/example.com.zone" \
      "$TMPDIR/state/declarative-zones/example.com.zone.saved"
    if "$helper" reconcile "$knotd" "$knotc" "$keymgr" "$kzonecheck" \
      "$TMPDIR/prepare.conf" "$TMPDIR/state" split "$zone"; then
      echo "existing signed zone bootstrapped without its manifest" >&2
      exit 1
    fi
    mv "$TMPDIR/state/declarative-zones/example.com.zone.saved" \
      "$TMPDIR/state/declarative-zones/example.com.zone"
    cat > "$TMPDIR/zones/other.test.zone" <<EOF
    \$TTL 3600
    other.test. IN SOA ns.other.test. hostmaster.other.test. (1 3600 600 86400 60)
    other.test. IN NS ns.other.test.
    ns.other.test. IN A 203.0.113.10
    EOF
    sed 's/example.com./other.test./g' "$TMPDIR/setup.conf" > "$TMPDIR/other-bootstrap.conf"
    cp "$TMPDIR/prepare.conf" "$TMPDIR/expanded-prepare.conf"
    cp "$TMPDIR/normal.conf" "$TMPDIR/expanded-normal.conf"
    printf '  - domain: other.test.\n    template: default\n' \
      >> "$TMPDIR/expanded-prepare.conf"
    printf '  - domain: other.test.\n    template: default\n' \
      >> "$TMPDIR/expanded-normal.conf"
    "$helper" reconcile "$knotd" "$knotc" "$keymgr" "$kzonecheck" \
      "$TMPDIR/expanded-prepare.conf" "$TMPDIR/state" split \
      "$zone" "other.test.=$TMPDIR/zones/other.test.zone=$TMPDIR/other-bootstrap.conf"
    test -s "$TMPDIR/state/declarative-zones/other.test.zone"
    test "$("$keymgr" --config "$TMPDIR/expanded-normal.conf" example.com. list)" = "$existing_keys"
    "$knotd" --config "$TMPDIR/expanded-normal.conf" &
    daemon=$!
    for i in $(seq 1 100); do
      "$knotc" --config "$TMPDIR/expanded-normal.conf" status >/dev/null 2>&1 && break
      sleep 0.1
    done
    "$knotc" --config "$TMPDIR/expanded-normal.conf" zone-read example.com. dynamic.example.com. A \
      | grep -F 192.0.2.44
    "$knotc" --config "$TMPDIR/expanded-normal.conf" zone-read other.test. other.test. SOA \
      | grep -F ns.other.test.
    "$knotc" --config "$TMPDIR/expanded-normal.conf" stop
    wait "$daemon"
    trap - EXIT
    echo ok > "$out"
  '';
}

use super::{initialize, knotc, stop_daemon, verify_state, wait_for, Inputs, START_TIMEOUT};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct Record {
    owner: String,
    ttl: String,
    kind: String,
    data: String,
}

fn manifest_path(input: &Inputs, zone: &str) -> PathBuf {
    input
        .state
        .join("declarative-zones")
        .join(format!("{zone}zone"))
}

pub(super) fn bootstrap_missing(input: &Inputs) -> Result<(), String> {
    for zone in &input.zones {
        let path = manifest_path(input, &zone.name);
        if path.is_file() {
            continue;
        }
        let keys = Command::new(&input.keymgr)
            .arg("--config")
            .arg(&zone.bootstrap_config)
            .arg(&zone.name)
            .arg("list")
            .output()
            .map_err(|error| format!("inspect existing keys for {}: {error}", zone.name))?;
        if keys.status.success() && !keys.stdout.is_empty() {
            return Err(format!(
                "missing manifest for signed zone {}; restore its state before startup",
                zone.name
            ));
        }
        let mut isolated = input.clone();
        isolated.config = zone.bootstrap_config.clone();
        isolated.zones = vec![zone.clone()];
        let mut daemon = Command::new(&isolated.knotd)
            .arg("--config")
            .arg(&isolated.config)
            .stdin(Stdio::null())
            .spawn()
            .map_err(|error| format!("bootstrap {}: {error}", zone.name))?;
        let outcome = initialize(&isolated, &mut daemon);
        let stopped = stop_daemon(&isolated, &mut daemon);
        outcome?;
        stopped?;
        verify_state(&isolated)?;
        write_initial_manifests(&isolated)?;
    }
    Ok(())
}

fn canonical(input: &Inputs, file: &Path) -> Result<String, String> {
    let output = Command::new(&input.kzonecheck)
        .arg("--print")
        .arg(file)
        .output()
        .map_err(|error| format!("kzonecheck: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "invalid zone {}: {}",
            file.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| format!("zone is not UTF-8: {error}"))
}

fn parse(text: &str) -> Result<BTreeSet<Record>, String> {
    text.lines()
        .filter(|line| !line.is_empty() && !line.starts_with(';'))
        .map(|line| {
            let fields: Vec<_> = line.splitn(4, '\t').map(str::trim).collect();
            if fields.len() != 4 || fields.iter().any(|field| field.is_empty()) {
                return Err(format!("invalid canonical zone record: {line}"));
            }
            Ok(Record {
                owner: fields[0].into(),
                ttl: fields[1].into(),
                kind: fields[2].into(),
                data: fields[3].into(),
            })
        })
        .collect()
}

fn write_manifest(path: &Path, content: &str) -> Result<(), String> {
    let parent = path.parent().ok_or("manifest has no parent")?;
    fs::create_dir_all(parent).map_err(|error| format!("create manifest directory: {error}"))?;
    let temp = path.with_extension("zone.new");
    fs::write(&temp, content).map_err(|error| format!("write {}: {error}", temp.display()))?;
    fs::rename(&temp, path).map_err(|error| format!("install {}: {error}", path.display()))
}

pub(super) fn write_initial_manifests(input: &Inputs) -> Result<(), String> {
    for zone in &input.zones {
        let content = canonical(input, &zone.file)?;
        parse(&content)?;
        write_manifest(&manifest_path(input, &zone.name), &content)?;
    }
    Ok(())
}

pub(super) fn apply(input: &Inputs, daemon: &mut Child) -> Result<(), String> {
    wait_for(input, daemon, START_TIMEOUT, || {
        knotc(input, &["status"]).is_ok()
    })?;
    for zone in &input.zones {
        let path = manifest_path(input, &zone.name);
        let previous = fs::read_to_string(&path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        let current = canonical(input, &zone.file)?;
        let old = parse(&previous)?;
        let new = parse(&current)?;
        if old == new {
            continue;
        }
        knotc(input, &["zone-begin", &zone.name])?;
        let update = (|| {
            for record in old.difference(&new) {
                knotc(
                    input,
                    &[
                        "zone-unset",
                        &zone.name,
                        &record.owner,
                        &record.kind,
                        &record.data,
                    ],
                )?;
            }
            for record in new.difference(&old) {
                knotc(
                    input,
                    &[
                        "zone-set",
                        &zone.name,
                        &record.owner,
                        &record.ttl,
                        &record.kind,
                        &record.data,
                    ],
                )?;
            }
            knotc(input, &["zone-commit", &zone.name])?;
            Ok::<_, String>(())
        })();
        if let Err(error) = update {
            let _ = knotc(input, &["zone-abort", &zone.name]);
            return Err(error);
        }
        write_manifest(&path, &current)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_records_and_preserves_quoted_data() {
        let records = parse(";; header\nexample.com.\t3600\tTXT\t\"hello world\"\n").unwrap();
        assert_eq!(records.iter().next().unwrap().data, "\"hello world\"");
    }
}

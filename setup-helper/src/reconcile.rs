use super::{initialize, knotc, stop_daemon, verify_state, wait_for, Inputs, START_TIMEOUT};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with(';'))
        .map(|line| {
            let mut tail = line.trim();
            let mut next = || {
                let end = tail.find(char::is_whitespace)?;
                let (field, remaining) = tail.split_at(end);
                tail = remaining.trim_start();
                Some(field)
            };
            let owner = next().ok_or_else(|| format!("invalid canonical zone record: {line}"))?;
            let ttl = next().ok_or_else(|| format!("invalid canonical zone record: {line}"))?;
            let kind = next().ok_or_else(|| format!("invalid canonical zone record: {line}"))?;
            if tail.is_empty() {
                return Err(format!("invalid canonical zone record: {line}"));
            }
            Ok(Record {
                owner: owner.into(),
                ttl: ttl.into(),
                kind: kind.into(),
                data: tail.into(),
            })
        })
        .collect()
}

fn write_manifest(path: &Path, content: &str) -> Result<(), String> {
    let parent = path.parent().ok_or("manifest has no parent")?;
    fs::create_dir_all(parent).map_err(|error| format!("create manifest directory: {error}"))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("protect manifest directory: {error}"))?;
    struct Temporary(PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let name = path
        .file_name()
        .ok_or("manifest has no filename")?
        .to_string_lossy();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("manifest clock: {error}"))?
        .as_nanos();
    let mut created = None;
    for attempt in 0..128 {
        let temp = parent.join(format!(
            ".{name}.{}.{stamp}.{attempt}.new",
            std::process::id()
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
        {
            Ok(output) => {
                created = Some((Temporary(temp), output));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("create private manifest temporary: {error}")),
        }
    }
    let (temporary, mut output) = created.ok_or("manifest temporary name space exhausted")?;
    output
        .write_all(content.as_bytes())
        .map_err(|error| format!("write manifest: {error}"))?;
    output
        .sync_all()
        .map_err(|error| format!("sync manifest: {error}"))?;
    drop(output);
    fs::rename(&temporary.0, path)
        .map_err(|error| format!("install {}: {error}", path.display()))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync manifest directory: {error}"))
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
    fn zone_manifests_are_private_crash_tolerant_and_clean_error_temporaries() {
        use std::os::unix::fs::MetadataExt;
        let root =
            std::env::temp_dir().join(format!("knot-private-manifest-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let path = root.join("declarative-zones/example.test.zone");
        write_manifest(&path, "first").unwrap();
        assert_eq!(
            fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        write_manifest(&path, "second").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
        fs::write(path.with_extension("zone.new"), "stale").unwrap();
        write_manifest(&path, "third").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "third");
        assert_eq!(
            fs::read_to_string(path.with_extension("zone.new")).unwrap(),
            "stale"
        );
        let blocked = path.parent().unwrap().join("blocked");
        fs::create_dir(&blocked).unwrap();
        assert!(write_manifest(&blocked, "fail").is_err());
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 3);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_canonical_records_and_preserves_quoted_data() {
        let records = parse(
            ";; header\nexample.com.\t3600\tTXT\t\"hello world\"\n\
             _verify.example.test.  86400  TXT     \"sample-token\"\n",
        )
        .unwrap();
        assert!(records
            .iter()
            .any(|record| record.data == "\"hello world\""));
        assert!(records
            .iter()
            .any(|record| record.data == "\"sample-token\""));
    }
}

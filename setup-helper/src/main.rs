#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

mod input;
mod reconcile;

use input::{parse_args, require_empty_state};

const START_TIMEOUT: Duration = Duration::from_secs(30);
const SIGN_TIMEOUT: Duration = Duration::from_secs(120);
const STOP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
struct Inputs {
    mode: Mode,
    knotd: PathBuf,
    knotc: PathBuf,
    keymgr: PathBuf,
    kzonecheck: PathBuf,
    config: PathBuf,
    state: PathBuf,
    single_type: bool,
    zones: Vec<Zone>,
}

#[derive(Clone, Copy)]
enum Mode {
    Initialize,
    Reconcile,
}

#[derive(Clone)]
struct Zone {
    name: String,
    file: PathBuf,
    bootstrap_config: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("knot-fresh-init: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let input = parse_args()?;
    match input.mode {
        Mode::Initialize => require_empty_state(&input.state)?,
        Mode::Reconcile => reconcile::bootstrap_missing(&input)?,
    }
    let mut daemon = Command::new(&input.knotd)
        .arg("--config")
        .arg(&input.config)
        .stdin(Stdio::null())
        .spawn()
        .map_err(|error| format!("start knotd: {error}"))?;
    let outcome = match input.mode {
        Mode::Initialize => initialize(&input, &mut daemon),
        Mode::Reconcile => reconcile::apply(&input, &mut daemon),
    };
    let stopped = stop_daemon(&input, &mut daemon);
    outcome?;
    stopped?;
    verify_state(&input)?;
    match input.mode {
        Mode::Initialize => reconcile::write_initial_manifests(&input),
        Mode::Reconcile => Ok(()),
    }
}

fn initialize(input: &Inputs, daemon: &mut Child) -> Result<(), String> {
    wait_for(input, daemon, START_TIMEOUT, || {
        knotc(input, &["status"]).is_ok()
    })?;
    for zone in &input.zones {
        let deadline = Instant::now() + SIGN_TIMEOUT;
        loop {
            if let Ok(output) = knotc(input, &["-b", "zone-sign", &zone.name]) {
                if output.status.success() && zone_ready(input, &zone.name)? {
                    break;
                }
            }
            if daemon
                .try_wait()
                .map_err(|error| error.to_string())?
                .is_some()
            {
                return Err(format!("knotd exited before {} was signed", zone.name));
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out signing {}", zone.name));
            }
            thread::sleep(Duration::from_millis(250));
        }
    }
    Ok(())
}

fn zone_ready(input: &Inputs, zone: &str) -> Result<bool, String> {
    if knotc(input, &["zone-status", zone]).is_err() {
        return Ok(false);
    }
    let output = Command::new(&input.keymgr)
        .arg("--config")
        .arg(&input.config)
        .arg(zone)
        .arg("list")
        .output()
        .map_err(|error| format!("keymgr: {error}"))?;
    if !output.status.success() {
        return Ok(false);
    }
    let keys = String::from_utf8_lossy(&output.stdout);
    Ok(keys.contains("KSK") && (input.single_type || keys.contains("ZSK")))
}

fn knotc(input: &Inputs, action: &[&str]) -> Result<std::process::Output, String> {
    let output = Command::new(&input.knotc)
        .arg("--config")
        .arg(&input.config)
        .arg("--timeout")
        .arg("2")
        .args(action)
        .output()
        .map_err(|error| format!("knotc: {error}"))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "knotc {} failed: {}",
            action.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn wait_for(
    input: &Inputs,
    daemon: &mut Child,
    timeout: Duration,
    mut ready: impl FnMut() -> bool,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if ready() {
            return Ok(());
        }
        if daemon
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("knotd exited during startup".into());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err(format!(
        "timed out waiting for Knot control socket at {}",
        input.config.display()
    ))
}

fn stop_daemon(input: &Inputs, daemon: &mut Child) -> Result<(), String> {
    if daemon
        .try_wait()
        .map_err(|error| error.to_string())?
        .is_none()
    {
        if knotc(input, &["stop"]).is_err() {
            daemon
                .kill()
                .map_err(|error| format!("kill knotd: {error}"))?;
        }
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    loop {
        if let Some(status) = daemon.try_wait().map_err(|error| error.to_string())? {
            if status.success() {
                return Ok(());
            }
            return Err(format!("knotd exited with {status}"));
        }
        if Instant::now() >= deadline {
            daemon
                .kill()
                .map_err(|error| format!("kill hung knotd: {error}"))?;
            return Err("knotd did not stop cleanly".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn verify_state(input: &Inputs) -> Result<(), String> {
    for relative in ["keys/data.mdb", "journal/data.mdb", "timers/data.mdb"] {
        let path = input.state.join(relative);
        if !path.is_file() {
            return Err(format!("Knot did not create {}", path.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs};

    #[test]
    fn rejects_existing_state_before_starting_daemon() {
        let path = env::temp_dir().join(format!("knot-init-test-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("keys"), b"existing").unwrap();
        assert!(require_empty_state(&path).is_err());
        fs::remove_dir_all(path).unwrap();
    }
}

use super::{Inputs, Mode, Zone};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn parse_args() -> Result<Inputs, String> {
    let mut args = env::args_os().skip(1);
    let mut next = || {
        args.next()
            .ok_or_else(|| "missing setup argument".to_string())
    };
    let mode = match next()?.to_str() {
        Some("initialize") => Mode::Initialize,
        Some("reconcile") => Mode::Reconcile,
        _ => return Err("mode must be initialize or reconcile".into()),
    };
    let knotd = PathBuf::from(next()?);
    let knotc = PathBuf::from(next()?);
    let keymgr = PathBuf::from(next()?);
    let kzonecheck = PathBuf::from(next()?);
    let config = PathBuf::from(next()?);
    let state = PathBuf::from(next()?);
    let single_type = match next()?.to_str() {
        Some("single") => true,
        Some("split") => false,
        _ => return Err("signing mode must be single or split".into()),
    };
    let zones = args
        .map(|arg| {
            let value = arg
                .into_string()
                .map_err(|_| "zone argument is not UTF-8".to_string())?;
            let mut parts = value.splitn(3, '=');
            let name = parts.next().ok_or("zone name is missing")?;
            let file = parts.next().ok_or("zone file is missing")?;
            let bootstrap_config =
                PathBuf::from(parts.next().ok_or("bootstrap config is missing")?);
            let file = PathBuf::from(file);
            if !name.ends_with('.')
                || !file.is_absolute()
                || !bootstrap_config.is_absolute()
                || name.contains('/')
            {
                return Err(
                    "zone must be a fully qualified name with absolute file and bootstrap config"
                        .into(),
                );
            }
            Ok(Zone {
                name: name.to_string(),
                file,
                bootstrap_config,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if zones.is_empty() {
        return Err("at least one primary zone is required".into());
    }
    if [&knotd, &knotc, &keymgr, &kzonecheck, &config, &state]
        .iter()
        .any(|path| !path.is_absolute())
    {
        return Err("all binary, config, and state paths must be absolute".into());
    }
    Ok(Inputs {
        mode,
        knotd,
        knotc,
        keymgr,
        kzonecheck,
        config,
        state,
        single_type,
        zones,
    })
}

pub(super) fn require_empty_state(state: &Path) -> Result<(), String> {
    let mut entries = fs::read_dir(state)
        .map_err(|error| format!("cannot inspect {}: {error}", state.display()))?;
    if entries.next().is_some() {
        return Err(format!(
            "{} is not empty; refusing fresh initialization",
            state.display()
        ));
    }
    Ok(())
}

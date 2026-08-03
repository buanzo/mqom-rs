use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

const ORACLE_COMMIT: &str = "01af24ad01203ad08e84f71f59cfa47cbb574050";
const PROFILE_CFLAGS: &str = "-DMQOM2_PARAM_SECURITY=128 -DMQOM2_PARAM_BASE_FIELD=4 -DMQOM2_PARAM_TRADEOFF=1 -DMQOM2_PARAM_NBROUNDS=5";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    let Some(command) = arguments.next() else {
        return Err(usage());
    };
    if command != "oracle" {
        return Err(usage());
    }

    let Some(flag) = arguments.next() else {
        return Err(usage());
    };
    if flag != "--source" {
        return Err(usage());
    }
    let Some(source) = arguments.next() else {
        return Err(usage());
    };
    if arguments.next().is_some() {
        return Err(usage());
    }

    prepare_oracle(&PathBuf::from(source))
}

fn usage() -> String {
    "usage: cargo xtask oracle --source /absolute/path/to/mqom-v2".to_owned()
}

fn prepare_oracle(source: &Path) -> Result<(), String> {
    if !source.is_absolute() {
        return Err("--source must be an absolute path".to_owned());
    }
    if !source.join(".git").exists() {
        return Err(format!("{} is not a Git checkout", source.display()));
    }

    let actual_commit =
        command_output(Command::new("git").args(["-C", path_text(source)?, "rev-parse", "HEAD"]))?;
    if actual_commit != ORACLE_COMMIT {
        return Err(format!(
            "oracle must be MQOM v2.1.1 commit {ORACLE_COMMIT}; found {actual_commit}"
        ));
    }

    run_command(Command::new("git").args([
        "-C",
        path_text(source)?,
        "diff",
        "--quiet",
        "--ignore-submodules",
        "HEAD",
        "--",
    ]))
    .map_err(|_| "oracle checkout has tracked modifications".to_owned())?;

    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "xtask has no workspace parent".to_owned())?;
    let destination = workspace.join("target/oracle").join(ORACLE_COMMIT);
    let oracle_root = workspace.join("target/oracle");
    if destination.exists() {
        let canonical_destination = destination
            .canonicalize()
            .map_err(|error| format!("cannot resolve {}: {error}", destination.display()))?;
        let canonical_root = oracle_root
            .canonicalize()
            .map_err(|error| format!("cannot resolve {}: {error}", oracle_root.display()))?;
        if !canonical_destination.starts_with(&canonical_root) {
            return Err("refusing to replace an oracle path outside target/oracle".to_owned());
        }
        fs::remove_dir_all(&canonical_destination).map_err(|error| {
            format!("cannot clear {}: {error}", canonical_destination.display())
        })?;
    }
    fs::create_dir_all(&oracle_root)
        .map_err(|error| format!("cannot create {}: {error}", oracle_root.display()))?;

    run_command(
        Command::new("git")
            .args(["clone", "--quiet", "--no-local", "--no-checkout"])
            .arg(source)
            .arg(&destination),
    )?;
    run_command(Command::new("git").arg("-C").arg(&destination).args([
        "checkout",
        "--quiet",
        "--detach",
        ORACLE_COMMIT,
    ]))?;

    run_command(
        Command::new("make")
            .arg("-C")
            .arg(&destination)
            .args(["-j2", "kat_gen", "kat_check"])
            .env("EXTRA_CFLAGS", PROFILE_CFLAGS)
            .env("FORCE_PLATFORM_REF", "1"),
    )?;
    run_command(Command::new(destination.join("kat_gen")).current_dir(&destination))?;

    let response = destination.join("PQCsignKAT_88.rsp");
    let contents = fs::read_to_string(&response)
        .map_err(|error| format!("cannot read {}: {error}", response.display()))?;
    let case_count = contents
        .lines()
        .filter(|line| line.starts_with("count = "))
        .count();
    if case_count != 100 {
        return Err(format!(
            "expected 100 KAT cases in {}, found {case_count}",
            response.display()
        ));
    }

    println!("verified oracle commit: {ORACLE_COMMIT}");
    println!("generated 100 KAT cases: {}", response.display());
    Ok(())
}

fn path_text(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn command_output(command: &mut Command) -> Result<String, String> {
    let description = format!("{command:?}");
    let output = command
        .output()
        .map_err(|error| format!("cannot run {description}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{description} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_command(command: &mut Command) -> Result<(), String> {
    let description = format!("{command:?}");
    let status = command
        .status()
        .map_err(|error| format!("cannot run {description}: {error}"))?;
    if !status.success() {
        return Err(format!("{description} exited with {status}"));
    }
    Ok(())
}

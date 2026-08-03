use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use mqom::mqom2_l1_gf16_short_r5::{Signature, VerifyingKey};

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
    let verified_count = verify_response(&contents)?;

    println!("verified oracle commit: {ORACLE_COMMIT}");
    println!("generated 100 KAT cases: {}", response.display());
    println!("verified {verified_count} KAT signatures in native Rust");
    Ok(())
}

#[derive(Default)]
struct KatCase<'a> {
    count: Option<usize>,
    message_len: Option<usize>,
    message: Option<&'a str>,
    public_key: Option<&'a str>,
    signed_message_len: Option<usize>,
    signed_message: Option<&'a str>,
}

fn verify_response(contents: &str) -> Result<usize, String> {
    let mut current = KatCase::default();
    let mut verified = 0;

    for line in contents.lines().chain([""]) {
        let line = line.trim();
        if line.is_empty() {
            if current.count.is_some() {
                verify_case(&current, verified == 0)?;
                verified += 1;
                current = KatCase::default();
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }

        let Some((name, value)) = line.split_once(" = ") else {
            return Err(format!("malformed KAT line: {line}"));
        };
        match name {
            "count" => current.count = Some(parse_decimal(name, value)?),
            "mlen" => current.message_len = Some(parse_decimal(name, value)?),
            "msg" => current.message = Some(value),
            "pk" => current.public_key = Some(value),
            "smlen" => current.signed_message_len = Some(parse_decimal(name, value)?),
            "sm" => current.signed_message = Some(value),
            _ => {}
        }
    }

    if verified != 100 {
        return Err(format!(
            "native verifier expected 100 cases, found {verified}"
        ));
    }
    Ok(verified)
}

fn parse_decimal(name: &str, value: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|error| format!("invalid {name} value {value}: {error}"))
}

fn verify_case(case: &KatCase<'_>, test_mutations: bool) -> Result<(), String> {
    let count = case
        .count
        .ok_or_else(|| "KAT case has no count".to_owned())?;
    let message_len = case
        .message_len
        .ok_or_else(|| format!("KAT case {count} has no mlen"))?;
    let message = decode_hex(
        case.message
            .ok_or_else(|| format!("KAT case {count} has no msg"))?,
    )?;
    let public_key_bytes = decode_hex(
        case.public_key
            .ok_or_else(|| format!("KAT case {count} has no pk"))?,
    )?;
    let signed_message_len = case
        .signed_message_len
        .ok_or_else(|| format!("KAT case {count} has no smlen"))?;
    let signed_message = decode_hex(
        case.signed_message
            .ok_or_else(|| format!("KAT case {count} has no sm"))?,
    )?;

    if message.len() != message_len
        || signed_message.len() != signed_message_len
        || signed_message.get(..message_len) != Some(message.as_slice())
    {
        return Err(format!("KAT case {count} has inconsistent message lengths"));
    }
    let signature_bytes = signed_message
        .get(message_len..)
        .ok_or_else(|| format!("KAT case {count} has no detached signature"))?;
    let public_key = VerifyingKey::from_slice(&public_key_bytes)
        .map_err(|error| format!("KAT case {count} public key: {error}"))?;
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|error| format!("KAT case {count} signature: {error}"))?;
    public_key
        .verify(&message, &signature)
        .map_err(|_| format!("native verification failed for KAT case {count}"))?;

    if test_mutations {
        reject_targeted_mutations(count, &public_key_bytes, &message, signature_bytes)?;
    }
    Ok(())
}

fn reject_targeted_mutations(
    count: usize,
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), String> {
    for position in [0, 16, 80, 272, signature_bytes.len() - 1] {
        let mut mutated = signature_bytes.to_vec();
        mutated[position] ^= 1;
        let signature = Signature::from_slice(&mutated)
            .map_err(|error| format!("mutation parse for case {count}: {error}"))?;
        let public_key = VerifyingKey::from_slice(public_key_bytes)
            .map_err(|error| format!("mutation key for case {count}: {error}"))?;
        if public_key.verify(message, &signature).is_ok() {
            return Err(format!(
                "KAT case {count} accepted signature mutation at byte {position}"
            ));
        }
    }

    let mut mutated_message = message.to_vec();
    let Some(first_byte) = mutated_message.first_mut() else {
        return Err(format!("KAT case {count} has an empty mutation message"));
    };
    *first_byte ^= 1;
    let public_key = VerifyingKey::from_slice(public_key_bytes)
        .map_err(|error| format!("message mutation key for case {count}: {error}"))?;
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|error| format!("message mutation signature for case {count}: {error}"))?;
    if public_key.verify(&mutated_message, &signature).is_ok() {
        return Err(format!("KAT case {count} accepted a message mutation"));
    }

    let mut mutated_key = public_key_bytes.to_vec();
    let Some(last_byte) = mutated_key.last_mut() else {
        return Err(format!("KAT case {count} has an empty public key"));
    };
    *last_byte ^= 1;
    let public_key = VerifyingKey::from_slice(&mutated_key)
        .map_err(|error| format!("public-key mutation for case {count}: {error}"))?;
    if public_key.verify(message, &signature).is_ok() {
        return Err(format!("KAT case {count} accepted a public-key mutation"));
    }
    Ok(())
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.len() % 2 != 0 {
        return Err("hex value has odd length".to_owned());
    }

    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0])?;
            let low = decode_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", char::from(byte))),
    }
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

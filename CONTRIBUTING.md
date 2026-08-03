# Contributing

The repository is public from the beginning so that design, implementation,
and interoperability evidence can be inspected as the research progresses.

Issues, design discussion, cryptographic review, independent test results, and
bug reports are welcome. Please keep reports technically specific and include
the exact revision and parameter set involved.

The project is currently in a steward-only implementation phase. Outside code
pull requests may be reviewed as proposals, but they will not be merged yet.
This avoids unclear provenance while the contribution policy receives the
required legal review. Do not submit code copied or translated from another
implementation.

For project-owned changes:

- preserve `no_std + alloc` support;
- do not introduce unsafe Rust;
- keep secret-dependent control flow and memory access out of cryptographic
  paths;
- add tests before changing serialized behavior;
- run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, and `cargo test --workspace`;
- never commit upstream C, generated KAT files, credentials, or large build
  artifacts.

Security vulnerabilities should follow [SECURITY.md](SECURITY.md), not a
public issue.


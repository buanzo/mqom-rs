# mqom-rs

`mqom-rs` is an unofficial, experimental native Rust implementation of the
[MQOM v2](https://mqom.org/) post-quantum signature proposal.

The first target is `MQOM2-L1-gf16-short-r5` from upstream release
[`v2.1.1`](https://github.com/mqom/mqom-v2/tree/v2.1.1). Work currently covers
the public encodings, parameter checks, GF(16), SHAKE128 transcript foundation,
and a pinned upstream conformance-oracle workflow. Native verification is the
next interoperability milestone; key generation and signing follow it.

> [!WARNING]
> This is research software. It is incomplete, has not been independently
> audited, and must not be used to protect sensitive or production data.

## Design boundary

- Native Rust implementation; no FFI or C-backed runtime.
- `no_std + alloc` library with caller-supplied randomness planned for all
  secret-key operations.
- The official C implementation is used only as a separately obtained test
  oracle. Its source and generated KAT files are not vendored or packaged.
- The implementation target remains v2.1.1 until one complete profile is
  interoperable.

## Build and test

The minimum supported Rust version is 1.85.

```console
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo check --lib --target wasm32-unknown-unknown
```

To prepare the upstream oracle, separately clone MQOM v2.1.1 and provide its
absolute path. The command refuses modified or unexpected revisions and builds
an isolated copy under ignored `target/` storage.

```console
git clone --branch v2.1.1 https://github.com/mqom/mqom-v2.git /path/to/mqom-v2
cargo xtask oracle --source /path/to/mqom-v2
```

The oracle build requires Git, Make, a C compiler, Python 3, and OpenSSL
development libraries. Cargo never downloads or links the C implementation.

## Project status and participation

See [ROADMAP.md](ROADMAP.md) for public milestones. Issues, research notes,
test reports, and design discussion are welcome. During the initial
steward-only implementation phase, outside code is reviewed but not merged;
see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Original project code and documentation are licensed under AGPL-3.0-only.
Upstream MQOM and Rust dependencies retain their own licenses; see
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).


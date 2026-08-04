# Threat model

This document defines the security boundaries used to review the frozen
`MQOM2-L1-gf16-short-r5` profile. It is a project-maintained model, not an
independent cryptographic or side-channel audit. The crate remains experimental
and unsuitable for production or sensitive data.

## Scope and assets

The shipped product surface is the `no_std + alloc` Rust library: exact-length
key and signature encodings, caller-randomized key generation and signing, and
detached verification. The repository does not provide a network service,
authentication layer, key database, or command interpreter.

Security-relevant assets are:

- signing-key material and derived per-signature state;
- signature authenticity and binding to the message and public key;
- correctness of the fixed v2.1.1 parameters, transcripts, and encodings;
- verifier safety and availability for arbitrary public inputs; and
- source, dependency, CI, package, and conformance-evidence integrity.

The `xtask/` oracle, `fuzz/` targets, benchmarks, and CI workflows are assurance
surfaces. They are not linked into the packaged runtime library.

## Trust boundaries

### Untrusted public inputs

A caller may provide any 60-byte public key, 2,916-byte signature, and
arbitrary-length message. Exact-length parsing, opening reconstruction,
transcript hashing, field arithmetic, allocation, and failure handling are
inside the verifier boundary. An embedding service must still provide request
admission and rate limits.

### Signing caller and randomness

The embedding application controls messages, invocation frequency, key
storage, and the `TryCryptoRng` supplied to key generation and signing. The
library propagates RNG failure but cannot prove that a caller-provided source
has sufficient entropy, independence, or operational security.

### Secret state and observables

Secret keys, signing randomness, tree nodes, masks, and intermediate field
values enter the signing path. Public outputs, timing, errors, debug output,
and memory lifetime must not reveal useful secret information. Zeroization is
defense in depth; it does not provide locked memory, prevent compiler-created
copies, or protect against a compromised process or host.

### Imported signing keys

An encoded secret key may come from untrusted or corrupted storage. The crate
must reject wrong lengths and any mismatch between its public component and
secret vector before it creates a signing object. External authentication,
encryption, authorization, rotation, and deletion remain application duties.

### Dependencies and target platform

Correctness and leakage behavior also depend on the RustCrypto AES and SHAKE
backends, `subtle`, `zeroize`, `rand_core`, the compiler, allocator, CPU, and
target. Source-level constant-time intent is not a formal proof about generated
machine code on every supported platform.

### Development oracle

The path-supplied MQOM C checkout and local build tools are trusted operator
inputs to a privileged development workflow. The oracle command must continue
to require an absolute, clean checkout at the exact pinned commit and keep its
C source, executables, and generated KAT material outside the Rust package.

### Repository and supply chain

Maintainer changes, dependency publishers, tool installers, GitHub Actions,
and the Rust toolchain can affect future evidence and artifacts. Locked builds,
pinned actions, dependency review, package-content checks, secret scanning, and
the separate oracle reduce this risk but cannot eliminate registry, runner, or
toolchain compromise.

## Security invariants

- Verification accepts only proofs satisfying every transcript, commitment,
  opening, challenge, equation, message-binding, and public-key-binding check.
- Encodings retain their exact canonical sizes and byte order. Other lengths
  fail before indexed parsing or expensive reconstruction.
- Key generation and signing obtain fresh secret randomness from the caller,
  propagate failure, and never return a partial or internally rejected
  signature.
- Imported signing keys are internally consistent before use.
- Domain separation, parameter constants, tree indexing, field
  representations, transcript order, and offsets remain interoperable with the
  pinned v2.1.1 profile.
- Public inputs do not cause memory unsafety, panic, uncontrolled allocation,
  pathological amplification, or acceptance through an error path.
- Secrets are not intentionally logged or formatted and are cleared from
  owned transient storage where practical.
- The packaged library remains native safe Rust without FFI, bundled C, or
  generated oracle artifacts.

## Primary attacker stories

1. A downstream service receives chosen keys, signatures, and messages. An
   attacker tries to forge, panic the process, or consume disproportionate CPU.
2. A signing service accepts chosen messages. An attacker observes signatures,
   timing, and success or failure to seek randomness reuse or key leakage.
3. Corrupted storage supplies a malformed signing key that attempts to bypass
   consistency checks.
4. A compromised dependency, build tool, action, runner, or oracle checkout
   attempts to alter evidence or future artifacts.

The first three become remotely reachable only through an embedding
application. That absence of a built-in route lowers current exposure but does
not excuse an intrinsic forgery, key-recovery, panic, or leakage flaw.

## Limits and exclusions

- Cryptanalysis of MQOM v2.1.1, AES, or SHAKE128 is distinct from an
  implementation error, though parameter transcription and protocol mistakes
  are in scope.
- Early rejection of public invalid inputs is permitted. Verification cost can
  still matter to downstream availability.
- Signing's nonce-grinding loop is variable-time over a nonce included in the
  public signature. Other secret-dependent timing remains in scope.
- Web vulnerabilities, transport security, tenant isolation, authentication,
  key-database controls, and server rate limiting belong to embedding systems.
- The experimental warning is not a security control against users who ignore
  it and does not reduce the intrinsic severity of a reproducible core break.

See [HARDENING.md](HARDENING.md) for current evidence and explicit gaps, and
[SECURITY.md](SECURITY.md) for vulnerability reporting.

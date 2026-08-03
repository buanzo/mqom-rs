# Third-party licenses and provenance

No upstream MQOM C source or generated KAT response is distributed in this
repository or its crate package.

## Reference implementation

- MQOM v2.1.1, copyright CryptoExperts and other upstream contributors.
- Repository: <https://github.com/mqom/mqom-v2>
- License: MIT. The license remains in the separately obtained upstream
  checkout used by the conformance workflow.

## Rust dependencies

The initial direct dependencies are maintained by their respective projects:

- `aes`: MIT OR Apache-2.0
- `rand_core`: MIT OR Apache-2.0
- `sha3`: MIT OR Apache-2.0
- `signature`: MIT OR Apache-2.0
- `subtle`: BSD-3-Clause
- `zeroize`: Apache-2.0 OR MIT

`Cargo.lock` is the authoritative resolved dependency inventory. Continuous
integration checks dependency licenses and advisories. Transitive dependencies
retain their own notices and terms.


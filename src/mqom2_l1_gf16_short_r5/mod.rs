//! Types for the `MQOM2-L1-gf16-short-r5` parameter set.
//!
//! Native key generation, signing, and verification are under active
//! implementation. The encoding types are intentionally available first so
//! that the conformance harness can exercise strict parsing without exposing
//! internal proof stages as public API.

use crate::params;
use core::fmt;
use signature::SignatureEncoding;
use zeroize::Zeroize;

/// Canonical profile label from MQOM v2.1.1.
pub const PARAMETER_SET: &str = "MQOM2-L1-gf16-short-r5";
/// Encoded public-key length in bytes.
pub const PUBLIC_KEY_SIZE: usize = params::PUBLIC_KEY_SIZE;
/// Encoded secret-key length in bytes.
pub const SECRET_KEY_SIZE: usize = params::SECRET_KEY_SIZE;
/// Encoded signature length in bytes.
pub const SIGNATURE_SIZE: usize = params::SIGNATURE_SIZE;

/// An encoding error for a profile value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError {
    expected: usize,
    actual: usize,
}

impl EncodingError {
    /// Expected byte length.
    #[must_use]
    pub const fn expected(self) -> usize {
        self.expected
    }

    /// Actual byte length.
    #[must_use]
    pub const fn actual(self) -> usize {
        self.actual
    }
}

impl fmt::Display for EncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid encoded length: expected {}, received {}",
            self.expected, self.actual
        )
    }
}

/// An MQOM verification key.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifyingKey([u8; PUBLIC_KEY_SIZE]);

impl VerifyingKey {
    /// Parse an exact-length canonical byte encoding.
    ///
    /// # Errors
    ///
    /// Returns [`EncodingError`] when `bytes` is not exactly
    /// [`PUBLIC_KEY_SIZE`] bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, EncodingError> {
        let encoded: [u8; PUBLIC_KEY_SIZE] = bytes.try_into().map_err(|_| EncodingError {
            expected: PUBLIC_KEY_SIZE,
            actual: bytes.len(),
        })?;
        Ok(Self(encoded))
    }

    /// Return the canonical byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for VerifyingKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VerifyingKey")
            .field(&self.0.as_slice())
            .finish()
    }
}

/// An MQOM signature.
#[derive(Clone, Eq, PartialEq)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    /// Parse an exact-length canonical byte encoding.
    ///
    /// # Errors
    ///
    /// Returns [`EncodingError`] when `bytes` is not exactly
    /// [`SIGNATURE_SIZE`] bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, EncodingError> {
        let encoded: [u8; SIGNATURE_SIZE] = bytes.try_into().map_err(|_| EncodingError {
            expected: SIGNATURE_SIZE,
            actual: bytes.len(),
        })?;
        Ok(Self(encoded))
    }

    /// Return the canonical byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Signature")
            .field("parameter_set", &PARAMETER_SET)
            .field("length", &SIGNATURE_SIZE)
            .finish_non_exhaustive()
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(bytes).map_err(|_| signature::Error::new())
    }
}

impl TryFrom<Signature> for [u8; SIGNATURE_SIZE] {
    type Error = signature::Error;

    fn try_from(signature: Signature) -> Result<Self, Self::Error> {
        Ok(signature.0)
    }
}

impl SignatureEncoding for Signature {
    type Repr = [u8; SIGNATURE_SIZE];
}

/// A zeroizing secret-key byte encoding.
pub struct SecretKeyBytes([u8; SECRET_KEY_SIZE]);

impl SecretKeyBytes {
    /// Borrow the secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for SecretKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretKeyBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKeyBytes([REDACTED])")
    }
}

impl Drop for SecretKeyBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// An MQOM signing key.
pub struct SigningKey([u8; SECRET_KEY_SIZE]);

impl SigningKey {
    /// Parse an exact-length secret-key encoding.
    ///
    /// Internal key consistency validation will be enabled with native key
    /// generation. Until then, callers should only import trusted test keys.
    ///
    /// # Errors
    ///
    /// Returns [`EncodingError`] when `bytes` is not exactly
    /// [`SECRET_KEY_SIZE`] bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, EncodingError> {
        let encoded: [u8; SECRET_KEY_SIZE] = bytes.try_into().map_err(|_| EncodingError {
            expected: SECRET_KEY_SIZE,
            actual: bytes.len(),
        })?;
        Ok(Self(encoded))
    }

    /// Return the public component embedded in the MQOM secret-key encoding.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        let mut encoded = [0u8; PUBLIC_KEY_SIZE];
        encoded.copy_from_slice(&self.0[..PUBLIC_KEY_SIZE]);
        VerifyingKey(encoded)
    }

    /// Export the key through a value which clears its storage on drop.
    #[must_use]
    pub fn to_bytes(&self) -> SecretKeyBytes {
        SecretKeyBytes(self.0)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigningKey([REDACTED])")
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_v2_1_1() {
        assert_eq!(PUBLIC_KEY_SIZE, 60);
        assert_eq!(SECRET_KEY_SIZE, 88);
        assert_eq!(SIGNATURE_SIZE, 2916);
    }

    #[test]
    fn exact_lengths_are_enforced() {
        assert!(VerifyingKey::from_slice(&[0u8; PUBLIC_KEY_SIZE]).is_ok());
        assert!(VerifyingKey::from_slice(&[0u8; PUBLIC_KEY_SIZE - 1]).is_err());
        assert!(Signature::from_slice(&[0u8; SIGNATURE_SIZE]).is_ok());
        assert!(Signature::from_slice(&[0u8; SIGNATURE_SIZE + 1]).is_err());
        assert!(SigningKey::from_slice(&[0u8; SECRET_KEY_SIZE]).is_ok());
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let key = SigningKey::from_slice(&[0x55; SECRET_KEY_SIZE]).unwrap();
        assert_eq!(alloc::format!("{key:?}"), "SigningKey([REDACTED])");
        assert_eq!(
            alloc::format!("{:?}", key.to_bytes()),
            "SecretKeyBytes([REDACTED])"
        );
    }

    #[test]
    fn public_component_is_embedded_at_the_start_of_secret_key() {
        let mut encoded = [0u8; SECRET_KEY_SIZE];
        for (index, byte) in encoded[..PUBLIC_KEY_SIZE].iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        let key = SigningKey::from_slice(&encoded).unwrap();
        assert_eq!(key.verifying_key().as_ref(), &encoded[..PUBLIC_KEY_SIZE]);
    }
}

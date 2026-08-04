//! Types for the `MQOM2-L1-gf16-short-r5` parameter set.
//!
//! Native verification, caller-randomized key generation, and randomized
//! signing are implemented and interoperable with the v2.1.1 KAT. Internal
//! proof stages are intentionally kept out of the public API.

use crate::params;
use core::fmt;
use rand_core::TryCryptoRng;
use signature::SignatureEncoding;
use zeroize::{Zeroize, Zeroizing};

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

impl core::error::Error for EncodingError {}

/// An error encountered while importing a signing key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningKeyError {
    /// The byte encoding has the wrong length.
    InvalidLength(EncodingError),
    /// The embedded public key does not match the secret vector.
    Inconsistent,
}

impl fmt::Display for SigningKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(error) => error.fmt(formatter),
            Self::Inconsistent => formatter.write_str("inconsistent MQOM signing key"),
        }
    }
}

impl core::error::Error for SigningKeyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InvalidLength(error) => Some(error),
            Self::Inconsistent => None,
        }
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

    /// Verify an MQOM signature over `message`.
    ///
    /// # Errors
    ///
    /// Returns an opaque signature error if any transcript, opening, or proof
    /// check fails.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        <Self as signature::Verifier<Signature>>::verify(self, message, signature)
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

impl signature::Verifier<Signature> for VerifyingKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        crate::verify::verify(&self.0, message, &signature.0)
            .then_some(())
            .ok_or_else(signature::Error::new)
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
    /// Generate a fresh signing key using caller-supplied cryptographic
    /// randomness.
    ///
    /// # Errors
    ///
    /// Returns an opaque error if the randomness source fails or the fixed
    /// profile cannot be expanded.
    pub fn generate<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, signature::Error> {
        let mut seed = Zeroizing::new([0u8; crate::keygen::KEYGEN_SEED_SIZE]);
        rng.try_fill_bytes(seed.as_mut())
            .map_err(|_| signature::Error::new())?;
        crate::keygen::keypair_from_seed(&seed)
            .map(|(secret_key, _)| Self(secret_key))
            .ok_or_else(signature::Error::new)
    }

    /// Sign `message` using caller-supplied cryptographic randomness.
    ///
    /// # Errors
    ///
    /// Returns an opaque error if the randomness source fails, the imported
    /// secret key is inconsistent, or signature construction fails.
    pub fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<Signature, signature::Error> {
        self.try_sign_inner(rng, message)
    }

    fn try_sign_inner<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<Signature, signature::Error> {
        let mut master_seed = Zeroizing::new([0u8; params::SEED_SIZE]);
        rng.try_fill_bytes(master_seed.as_mut())
            .map_err(|_| signature::Error::new())?;
        let mut salt = Zeroizing::new([0u8; params::SALT_SIZE]);
        rng.try_fill_bytes(salt.as_mut())
            .map_err(|_| signature::Error::new())?;

        crate::sign::sign(&self.0, message, &master_seed, &salt)
            .map(Signature)
            .ok_or_else(signature::Error::new)
    }

    /// Parse and validate a canonical secret-key encoding.
    ///
    /// # Errors
    ///
    /// Returns [`SigningKeyError`] when the length is wrong or the embedded
    /// public key is inconsistent with the secret vector.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SigningKeyError> {
        let encoded: [u8; SECRET_KEY_SIZE] = bytes.try_into().map_err(|_| {
            SigningKeyError::InvalidLength(EncodingError {
                expected: SECRET_KEY_SIZE,
                actual: bytes.len(),
            })
        })?;
        if !crate::keygen::secret_key_is_consistent(&encoded) {
            return Err(SigningKeyError::Inconsistent);
        }
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

impl signature::Keypair for SigningKey {
    type VerifyingKey = VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        Self::verifying_key(self)
    }
}

impl signature::RandomizedSigner<Signature> for SigningKey {
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<Signature, signature::Error> {
        self.try_sign_inner(rng, message)
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
    use core::convert::Infallible;
    use rand_core::{TryCryptoRng, TryRng};

    struct TestRng(u8);

    impl TryRng for TestRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0u8; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0u8; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            for byte in destination {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for TestRng {}

    #[derive(Debug)]
    struct TestRngError;

    impl fmt::Display for TestRngError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("test RNG failure")
        }
    }

    impl core::error::Error for TestRngError {}

    struct FailingRng;

    impl TryRng for FailingRng {
        type Error = TestRngError;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(TestRngError)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(TestRngError)
        }

        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), Self::Error> {
            Err(TestRngError)
        }
    }

    impl TryCryptoRng for FailingRng {}

    fn test_signing_key() -> SigningKey {
        let seed = core::array::from_fn(|index| u8::try_from(index).unwrap());
        let (encoded, _) = crate::keygen::keypair_from_seed(&seed).unwrap();
        SigningKey::from_slice(&encoded).unwrap()
    }

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
        assert!(SigningKey::from_slice(&[0u8; SECRET_KEY_SIZE - 1]).is_err());
        assert!(SigningKey::from_slice(test_signing_key().to_bytes().as_ref()).is_ok());
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let key = test_signing_key();
        assert_eq!(alloc::format!("{key:?}"), "SigningKey([REDACTED])");
        assert_eq!(
            alloc::format!("{:?}", key.to_bytes()),
            "SecretKeyBytes([REDACTED])"
        );
    }

    #[test]
    fn public_component_is_embedded_at_the_start_of_secret_key() {
        let key = test_signing_key();
        let encoded = key.to_bytes();
        assert_eq!(
            key.verifying_key().as_ref(),
            &encoded.as_ref()[..PUBLIC_KEY_SIZE]
        );
    }

    #[test]
    fn inconsistent_secret_keys_are_rejected() {
        let key = test_signing_key();
        let mut encoded = key.to_bytes().0;
        encoded[PUBLIC_KEY_SIZE] ^= 1;
        assert_eq!(
            SigningKey::from_slice(&encoded).unwrap_err(),
            SigningKeyError::Inconsistent
        );
    }

    #[test]
    fn generated_keys_sign_verify_and_reject_mutations() {
        let mut rng = TestRng(0);
        let key = SigningKey::generate(&mut rng).unwrap();
        let verifying_key = key.verifying_key();
        let message = b"native MQOM";
        let signature = key.try_sign_with_rng(&mut rng, message).unwrap();
        verifying_key.verify(message, &signature).unwrap();

        for position in [0, 16, 48, 80, 272, SIGNATURE_SIZE - 1] {
            let mut encoded = signature.to_bytes();
            encoded[position] ^= 1;
            let mutated = Signature::from_slice(&encoded).unwrap();
            assert!(verifying_key.verify(message, &mutated).is_err());
        }

        let mut mutated_message = *message;
        mutated_message[0] ^= 1;
        assert!(verifying_key.verify(&mutated_message, &signature).is_err());

        let mut mutated_key = verifying_key.to_bytes();
        mutated_key[PUBLIC_KEY_SIZE - 1] ^= 1;
        assert!(
            VerifyingKey::from_slice(&mutated_key)
                .unwrap()
                .verify(message, &signature)
                .is_err()
        );
    }

    #[test]
    fn randomness_failures_are_propagated() {
        assert!(SigningKey::generate(&mut FailingRng).is_err());

        let key = test_signing_key();
        assert!(
            key.try_sign_with_rng(&mut FailingRng, b"native MQOM")
                .is_err()
        );
    }
}

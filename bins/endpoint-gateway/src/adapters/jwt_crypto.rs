//! Bearer signatures verified with `ring` rather than `jsonwebtoken`'s pure-Rust backend.
//!
//! The cost test (`src/cost.rs`) put a first-seen ES256 bearer at ~220 µs, a thousand times
//! everything else on the `/auth` path — and every unique signed token is a first sight, which
//! makes it a CPU-flood vector as well as a latency. `ring` verifies the same signature in a
//! fraction of that, and it is already in the tree as rustls's provider, so this costs the build
//! nothing new and keeps the promise `Cargo.toml` makes: no C toolchain, which is why `aws-lc-rs`
//! is not the answer.
//!
//! Only the algorithms [`super::oidc::ALLOWED_ALGORITHMS`] admits are taken over — RS256, RS384,
//! RS512 and ES256. Everything else, signing included (tests mint tokens), is handed to
//! `jsonwebtoken`'s own `rust_crypto` provider unchanged, so nothing outside the verification of
//! an admitted algorithm changes behaviour.
//!
//! **One deliberate tightening:** `ring` verifies RSA only with moduli of 2048 to 8192 bits. A
//! key under 2048 bits — which no supported identity provider issues by default and every current
//! guideline refuses — no longer verifies at all, where `rust_crypto` would have accepted it.

use jsonwebtoken::crypto::{CryptoProvider, JwkUtils, JwtSigner, JwtVerifier, rust_crypto};
use jsonwebtoken::errors::{ErrorKind, Result};
use jsonwebtoken::jwk::{EllipticCurve, ThumbprintHash};
use jsonwebtoken::signature::{Error as SignatureError, Verifier};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, DecodingKeyKind, EncodingKey};
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512, RsaParameters, RsaPublicKeyComponents, UnparsedPublicKey,
    VerificationAlgorithm,
};

/// The provider: `ring` for the admitted algorithms, `rust_crypto` for the rest.
pub static RING_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: new_signer,
    verifier_factory: new_verifier,
    jwk_utils: JwkUtils {
        extract_rsa_public_key_components,
        extract_ec_public_key_coordinates,
        compute_digest,
    },
};

/// Make [`RING_PROVIDER`] `jsonwebtoken`'s process default. Idempotent; must run before the
/// first signature is signed or verified, because the first use fixes the default for the life
/// of the process — which is why [`super::oidc::JwksVerifier::new`] calls it as well as `main`.
pub fn install() {
    if let Err(installed) = RING_PROVIDER.install_default()
        && !std::ptr::eq(installed, &RING_PROVIDER)
    {
        eprintln!(
            "WARN endpoint-gateway: a JWT crypto provider was fixed before ours could be \
             installed; bearer signatures are verified with it instead of ring"
        );
    }
}

/// Whether `ring` is the provider bearer signatures go through — for the startup line.
pub fn installed() -> bool {
    match RING_PROVIDER.install_default() {
        Ok(()) => true,
        Err(installed) => std::ptr::eq(installed, &RING_PROVIDER),
    }
}

fn new_signer(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
    (rust_crypto::DEFAULT_PROVIDER.signer_factory)(algorithm, key)
}

fn extract_rsa_public_key_components(key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    (rust_crypto::DEFAULT_PROVIDER
        .jwk_utils
        .extract_rsa_public_key_components)(key)
}

fn extract_ec_public_key_coordinates(
    key: &[u8],
    algorithm: Algorithm,
) -> Result<(EllipticCurve, Vec<u8>, Vec<u8>)> {
    (rust_crypto::DEFAULT_PROVIDER
        .jwk_utils
        .extract_ec_public_key_coordinates)(key, algorithm)
}

fn compute_digest(data: &[u8], hash: ThumbprintHash) -> Vec<u8> {
    (rust_crypto::DEFAULT_PROVIDER.jwk_utils.compute_digest)(data, hash)
}

/// The `ring` verification for an admitted algorithm, and the key family it needs.
fn ring_algorithm(algorithm: Algorithm) -> Option<(AlgorithmFamily, Ring)> {
    match algorithm {
        Algorithm::ES256 => Some((AlgorithmFamily::Ec, Ring::Ecdsa(&ECDSA_P256_SHA256_FIXED))),
        Algorithm::RS256 => Some((AlgorithmFamily::Rsa, Ring::Rsa(&RSA_PKCS1_2048_8192_SHA256))),
        Algorithm::RS384 => Some((AlgorithmFamily::Rsa, Ring::Rsa(&RSA_PKCS1_2048_8192_SHA384))),
        Algorithm::RS512 => Some((AlgorithmFamily::Rsa, Ring::Rsa(&RSA_PKCS1_2048_8192_SHA512))),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum Ring {
    Ecdsa(&'static dyn VerificationAlgorithm),
    Rsa(&'static RsaParameters),
}

/// The public key, in the two forms a [`DecodingKey`] can hold it: bytes (a SEC1 point for EC,
/// PKCS#1 DER for RSA — what `rust_crypto` reads them as too) or an RSA modulus and exponent,
/// which is what a JWK yields.
enum PublicKey {
    Bytes(UnparsedPublicKey<Vec<u8>>),
    RsaComponents {
        parameters: &'static RsaParameters,
        n: Vec<u8>,
        e: Vec<u8>,
    },
}

struct RingVerifier {
    algorithm: Algorithm,
    key: PublicKey,
}

fn new_verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
    let Some((family, ring)) = ring_algorithm(*algorithm) else {
        return (rust_crypto::DEFAULT_PROVIDER.verifier_factory)(algorithm, key);
    };
    // The family check `rust_crypto` makes too: an EC key handed to an RSA algorithm (or the
    // reverse) is a malformed request, never a signature to try.
    if key.family() != family {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    let key = match (key.kind(), ring) {
        (DecodingKeyKind::SecretOrDer(bytes), Ring::Ecdsa(verification)) => {
            PublicKey::Bytes(UnparsedPublicKey::new(verification, bytes.clone()))
        }
        (DecodingKeyKind::SecretOrDer(bytes), Ring::Rsa(parameters)) => {
            PublicKey::Bytes(UnparsedPublicKey::new(parameters, bytes.clone()))
        }
        (DecodingKeyKind::RsaModulusExponent { n, e }, Ring::Rsa(parameters)) => {
            PublicKey::RsaComponents {
                parameters,
                n: n.clone(),
                e: e.clone(),
            }
        }
        (DecodingKeyKind::RsaModulusExponent { .. }, Ring::Ecdsa(_)) => {
            return Err(ErrorKind::InvalidKeyFormat.into());
        }
    };
    Ok(Box::new(RingVerifier {
        algorithm: *algorithm,
        key,
    }))
}

impl Verifier<Vec<u8>> for RingVerifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &Vec<u8>,
    ) -> std::result::Result<(), SignatureError> {
        let verified = match &self.key {
            PublicKey::Bytes(key) => key.verify(message, signature),
            PublicKey::RsaComponents { parameters, n, e } => {
                RsaPublicKeyComponents { n, e }.verify(parameters, message, signature)
            }
        };
        verified.map_err(|_| SignatureError::new())
    }
}

impl JwtVerifier for RingVerifier {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    fn es256_pair() -> (EcdsaKeyPair, DecodingKey) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let point = pair.public_key().as_ref().to_vec();
        let key = DecodingKey::from_ec_components(
            &B64.encode(&point[1..33]),
            &B64.encode(&point[33..65]),
        )
        .unwrap();
        (pair, key)
    }

    #[test]
    fn es256_verifies_its_own_signature_and_nothing_else() {
        let (pair, key) = es256_pair();
        let rng = ring::rand::SystemRandom::new();
        let message = b"header.payload";
        let signature = pair.sign(&rng, message).unwrap().as_ref().to_vec();
        let verifier = new_verifier(&Algorithm::ES256, &key).unwrap();
        assert!(verifier.verify(message, &signature).is_ok());
        assert!(verifier.verify(b"header.tampered", &signature).is_err());
        let (_, other) = es256_pair();
        let stranger = new_verifier(&Algorithm::ES256, &other).unwrap();
        assert!(stranger.verify(message, &signature).is_err());
    }

    /// RFC 7515 appendix A.2 — a published RS256 JWS and the public half of its key, so the RSA
    /// branch is checked against somebody else's vector rather than a key minted by this test.
    #[test]
    fn rs256_verifies_rfc_7515s_own_example() {
        // cspell:disable
        let n = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
        let e = "AQAB";
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
        // cspell:enable
        let key = DecodingKey::from_rsa_components(n, e).unwrap();
        let (message, signature) = token.rsplit_once('.').unwrap();
        let signature = B64.decode(signature).unwrap();
        let verifier = new_verifier(&Algorithm::RS256, &key).unwrap();
        assert!(verifier.verify(message.as_bytes(), &signature).is_ok());
        assert!(
            verifier
                .verify(b"eyJhbGciOiJSUzI1NiJ9.e30", &signature)
                .is_err()
        );
    }

    #[test]
    fn a_key_of_the_wrong_family_is_refused_before_any_signature_is_tried() {
        let (_, ec) = es256_pair();
        assert!(new_verifier(&Algorithm::RS256, &ec).is_err());
        let rsa = DecodingKey::from_rsa_components("AQAB", "AQAB").unwrap();
        assert!(new_verifier(&Algorithm::ES256, &rsa).is_err());
    }

    #[test]
    fn an_algorithm_ring_does_not_take_over_still_goes_to_rust_crypto() {
        let secret = DecodingKey::from_secret(b"not-a-gateway-algorithm");
        assert_eq!(
            new_verifier(&Algorithm::HS256, &secret)
                .unwrap()
                .algorithm(),
            Algorithm::HS256
        );
    }
}

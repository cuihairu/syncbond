//! SPAKE2 password-authenticated key exchange, RFC 9382, ciphersuite
//! SPAKE2-P256-SHA256-HKDF-HMAC (RFC 9382 Table 1).
//!
//! No primitives are implemented here: P-256 arithmetic comes from the
//! RustCrypto `p256` crate, hashing/KDF/MAC/MHF from `sha2`/`hkdf`/`hmac`/
//! `scrypt`. This module only assembles the RFC 9382 protocol steps and is
//! validated against all four RFC 9382 Appendix B test vectors.
//!
//! Design notes: docs/design/PROTOCOL.md (SPAKE2 vs SPAKE2+ selection) and
//! docs/design/pairing-codes.md (code policy).

use p256::elliptic_curve::bigint::{ArrayEncoding, NonZero, U512};
use p256::elliptic_curve::{sec1::ToEncodedPoint, PrimeField};
use p256::{FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// P-256 group order n (public curve constant, SEC 2 / RFC 9382).
const N_SCALAR_HEX: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

/// RFC 9382 §6 fixed point M for P-256 (compressed SEC1).
const M_HEX: &str = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
/// RFC 9382 §6 fixed point N for P-256 (compressed SEC1).
const N_HEX: &str = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

/// Parse a hex scalar and reduce it by the group order (test-vector helper).
pub fn scalar_from_hex(hex: &str) -> Scalar {
    let bytes = hex_to_bytes(hex);
    let mut wide = [0u8; 64];
    wide[64 - bytes.len()..].copy_from_slice(&bytes);
    wide_reduce(&wide)
}
const HALF_LEN: usize = 16;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum Spake2Error {
    #[error("received value is not a valid curve point")]
    InvalidPoint,
    #[error("generate_message() must run first")]
    MissingLocalShare,
    #[error("key confirmation failed")]
    ConfirmationFailed,
    #[error("protocol already completed or misused")]
    StateError,
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn point_from_hex(hex: &str) -> ProjectivePoint {
    let key = p256::PublicKey::from_sec1_bytes(&hex_to_bytes(hex))
        .expect("RFC 9382 fixed point is a valid P-256 point");
    ProjectivePoint::from(key.as_affine())
}

fn m_point() -> ProjectivePoint {
    point_from_hex(M_HEX)
}

fn n_point() -> ProjectivePoint {
    point_from_hex(N_HEX)
}

/// Derive the SPAKE2 scalar from a pairing code.
///
/// `w = OS2IP(scrypt("syncbond/w1/v1" || code, N=2^14, r=8, p=1, 64)) mod n`.
/// 64 output bytes avoid mod bias (NIST SP 800-56Ar3 suggestion); scrypt is
/// the RFC-recommended MHF. See docs/design/PROTOCOL.md for limits.
pub fn derive_w(code: &[u8]) -> Scalar {
    let params = scrypt::Params::new(14, 8, 1, 64).expect("fixed scrypt parameters");
    let mut ikm = Vec::with_capacity(code.len() + 17);
    ikm.extend_from_slice(b"syncbond/w1/v1");
    ikm.extend_from_slice(code);
    let mut wide = [0u8; 64];
    scrypt::scrypt(&ikm, &[], &params, &mut wide).expect("scrypt with fixed parameters");
    wide_reduce(&wide)
}

/// Modular reduction of a 512-bit value by the P-256 group order.
fn wide_reduce(wide: &[u8; 64]) -> Scalar {
    let mut order_bytes = [0u8; 64];
    order_bytes[32..].copy_from_slice(&hex_to_bytes(N_SCALAR_HEX));
    let order = NonZero::<U512>::new(U512::from_be_slice(&order_bytes)).expect("nonzero order");
    let reduced = U512::from_be_slice(wide).rem(&order);
    // reduced < n < 2^256, so the low 32 bytes carry the whole value.
    let reduced_bytes: [u8; 64] = reduced.to_be_byte_array().into();
    let repr: FieldBytes = *FieldBytes::from_slice(&reduced_bytes[32..]);
    // Input is already reduced; the repr is in range by construction.
    Scalar::from_repr(repr).unwrap()
}

fn random_scalar() -> Scalar {
    loop {
        let mut bytes = [0u8; 32];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut bytes);
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&bytes);
        let candidate = wide_reduce(&wide);
        if candidate != Scalar::ZERO {
            return candidate;
        }
    }
}

fn generator() -> ProjectivePoint {
    ProjectivePoint::from(p256::AffinePoint::GENERATOR)
}

fn decode_point(bytes: &[u8]) -> Result<ProjectivePoint, Spake2Error> {
    // PublicKey validates the encoding is on-curve and not the identity;
    // P-256 has cofactor 1, so on-curve implies the prime-order subgroup.
    let key = p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| Spake2Error::InvalidPoint)?;
    Ok(ProjectivePoint::from(key.as_affine()))
}

fn encode_point(point: &ProjectivePoint) -> Vec<u8> {
    point
        .to_affine()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn length_prefix(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn number_to_be_be(value: &Scalar) -> [u8; 32] {
    value.to_repr().into()
}

/// Build the RFC 9382 §3.3 transcript. Lengths are 8-byte little-endian;
/// w is big-endian padded to the length of p.
pub fn build_transcript(
    identity_a: &[u8],
    identity_b: &[u8],
    p_a: &[u8],
    p_b: &[u8],
    k: &[u8],
    w: &Scalar,
) -> Vec<u8> {
    let mut tt = Vec::with_capacity(512);
    for part in [
        length_prefix(identity_a),
        length_prefix(identity_b),
        length_prefix(p_a),
        length_prefix(p_b),
        length_prefix(k),
        length_prefix(&number_to_be_be(w)),
    ] {
        tt.extend_from_slice(&part);
    }
    tt
}

pub struct Spake2Secrets {
    /// 16-byte shared secret output of the protocol (RFC 9382 §4).
    pub ke: [u8; HALF_LEN],
    pub ka: [u8; HALF_LEN],
    pub kc_a: [u8; HALF_LEN],
    pub kc_b: [u8; HALF_LEN],
    pub transcript: Vec<u8>,
}

fn compute_secrets(
    k: &ProjectivePoint,
    identity_a: &[u8],
    identity_b: &[u8],
    p_a: &[u8],
    p_b: &[u8],
    w: &Scalar,
    aad: &[u8],
) -> Spake2Secrets {
    let k_bytes = encode_point(k);
    let transcript = build_transcript(identity_a, identity_b, p_a, p_b, &k_bytes, w);
    let digest = Sha256::digest(&transcript);
    let ke: [u8; HALF_LEN] = digest[..HALF_LEN].try_into().unwrap();
    let ka: [u8; HALF_LEN] = digest[HALF_LEN..].try_into().unwrap();
    let mut info = Vec::with_capacity(17 + aad.len());
    info.extend_from_slice(b"ConfirmationKeys");
    info.extend_from_slice(aad);
    let hk = hkdf::Hkdf::<Sha256>::new(None, &ka);
    let mut kcs = [0u8; 2 * HALF_LEN];
    hk.expand(&info, &mut kcs)
        .expect("32 bytes is a valid HKDF length");
    Spake2Secrets {
        ke,
        ka,
        kc_a: kcs[..HALF_LEN].try_into().unwrap(),
        kc_b: kcs[HALF_LEN..].try_into().unwrap(),
        transcript,
    }
}

fn mac(key: &[u8; HALF_LEN], message: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Party A of RFC 9382 §3: sends pA first, uses M. In syncbond this is `pair()`.
pub struct Spake2Initiator {
    w: Scalar,
    x: Scalar,
    p_a: Option<Vec<u8>>,
    identity_a: Vec<u8>,
    identity_b: Vec<u8>,
    aad: Vec<u8>,
}

/// Deterministic scalars for RFC 9382 Appendix B conformance tests.
pub struct TestScalars {
    pub w: Option<Scalar>,
    pub x: Option<Scalar>,
    pub y: Option<Scalar>,
}

impl Spake2Initiator {
    pub fn new(code: &[u8]) -> Self {
        Self::new_with_params(code, &[], &[], &[])
    }

    pub fn new_with_params(code: &[u8], identity_a: &[u8], identity_b: &[u8], aad: &[u8]) -> Self {
        Self {
            w: derive_w(code),
            x: random_scalar(),
            p_a: None,
            identity_a: identity_a.to_vec(),
            identity_b: identity_b.to_vec(),
            aad: aad.to_vec(),
        }
    }

    pub fn new_with_scalars(code: &[u8], test: &TestScalars) -> Self {
        Self::new(code).with_scalars(test)
    }

    /// Override the deterministic scalars (RFC 9382 Appendix B conformance).
    pub fn with_scalars(mut self, test: &TestScalars) -> Self {
        if let Some(w) = test.w {
            self.w = w;
        }
        if let Some(x) = test.x {
            self.x = x;
        }
        self
    }

    /// Generate and remember pA = w*M + x*P.
    pub fn generate_message(&mut self) -> Vec<u8> {
        let p = m_point() * self.w + generator() * self.x;
        let p_a = encode_point(&p);
        self.p_a = Some(p_a.clone());
        p_a
    }

    /// Process pB and derive the key schedule plus our confirmation MAC cA.
    pub fn process_response(&self, p_b: &[u8]) -> Result<(Spake2Secrets, [u8; 32]), Spake2Error> {
        let p_a = self.p_a.as_ref().ok_or(Spake2Error::MissingLocalShare)?;
        // K = h * x * (pB - w*N); cofactor h = 1 for P-256.
        let k = (decode_point(p_b)? - n_point() * self.w) * self.x;
        let secrets = compute_secrets(
            &k,
            &self.identity_a,
            &self.identity_b,
            p_a,
            p_b,
            &self.w,
            &self.aad,
        );
        let confirmation = mac(&secrets.kc_a, &secrets.transcript);
        Ok((secrets, confirmation))
    }

    /// Verify the responder confirmation cB.
    pub fn verify_confirmation(
        &self,
        secrets: &Spake2Secrets,
        c_b: &[u8; 32],
    ) -> Result<(), Spake2Error> {
        if mac(&secrets.kc_b, &secrets.transcript)[..] == c_b[..] {
            Ok(())
        } else {
            Err(Spake2Error::ConfirmationFailed)
        }
    }
}

/// Party B of RFC 9382 §3: answers with pB, uses N. In syncbond this is `accept()`.
pub struct Spake2Responder {
    w: Scalar,
    y: Scalar,
    identity_a: Vec<u8>,
    identity_b: Vec<u8>,
    aad: Vec<u8>,
}

impl Spake2Responder {
    pub fn new(code: &[u8]) -> Self {
        Self::new_with_params(code, &[], &[], &[])
    }

    pub fn new_with_params(code: &[u8], identity_a: &[u8], identity_b: &[u8], aad: &[u8]) -> Self {
        Self {
            w: derive_w(code),
            y: random_scalar(),
            identity_a: identity_a.to_vec(),
            identity_b: identity_b.to_vec(),
            aad: aad.to_vec(),
        }
    }

    pub fn new_with_scalars(code: &[u8], test: &TestScalars) -> Self {
        Self::new(code).with_scalars(test)
    }

    /// Override the deterministic scalars (RFC 9382 Appendix B conformance).
    pub fn with_scalars(mut self, test: &TestScalars) -> Self {
        if let Some(w) = test.w {
            self.w = w;
        }
        if let Some(y) = test.y {
            self.y = y;
        }
        self
    }

    /// Process pA, produce pB = w*N + y*P, the key schedule and our confirmation cB.
    pub fn process_intro(
        &mut self,
        p_a: &[u8],
    ) -> Result<(Vec<u8>, Spake2Secrets, [u8; 32]), Spake2Error> {
        // K = h * y * (pA - w*M); cofactor h = 1 for P-256.
        let k = (decode_point(p_a)? - m_point() * self.w) * self.y;
        let p_b = encode_point(&(n_point() * self.w + generator() * self.y));
        let secrets = compute_secrets(
            &k,
            &self.identity_a,
            &self.identity_b,
            p_a,
            &p_b,
            &self.w,
            &self.aad,
        );
        let confirmation = mac(&secrets.kc_b, &secrets.transcript);
        Ok((p_b, secrets, confirmation))
    }

    /// Verify the initiator confirmation cA.
    pub fn verify_confirmation(
        &self,
        secrets: &Spake2Secrets,
        c_a: &[u8; 32],
    ) -> Result<(), Spake2Error> {
        if mac(&secrets.kc_a, &secrets.transcript)[..] == c_a[..] {
            Ok(())
        } else {
            Err(Spake2Error::ConfirmationFailed)
        }
    }
}

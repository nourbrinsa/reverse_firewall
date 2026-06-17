use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error as DeError;

type HmacSha256 = Hmac<Sha256>;

pub fn random_scalar(rng: &mut impl RngCore) -> Scalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

pub fn base_point(x: &Scalar) -> RistrettoPoint {
    x * RISTRETTO_BASEPOINT_POINT
}

// ---------------------------------------------------------------------------
// Sérialisation de RistrettoPoint pour ElGamalCiphertext
// ---------------------------------------------------------------------------

fn ser_point<S: Serializer>(p: &RistrettoPoint, s: S) -> Result<S::Ok, S::Error> {
    p.compress().to_bytes().serialize(s)
}

fn de_point<'de, D: Deserializer<'de>>(d: D) -> Result<RistrettoPoint, D::Error> {
    let bytes = <[u8; 32]>::deserialize(d)?;
    CompressedRistretto(bytes)
        .decompress()
        .ok_or_else(|| D::Error::custom("point Ristretto invalide"))
}

// ---------------------------------------------------------------------------
// ElGamal haché (ECIES)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub r_point: RistrettoPoint,
    pub masked: [u8; 32],
}

pub fn kdf(p: &RistrettoPoint) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"session-key-derivation");
    hasher.update(p.compress().as_bytes());
    hasher.finalize().into()
}

pub fn concat_points(points: &[&RistrettoPoint]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in points {
        out.extend_from_slice(p.compress().as_bytes());
    }
    out
}

pub fn elgamal_encrypt(pk: &RistrettoPoint, msg: &[u8; 32], rng: &mut impl RngCore) -> ElGamalCiphertext {
    let r = random_scalar(rng);
    let r_point = base_point(&r);
    let shared = r * pk;
    let key = kdf(&shared);
    let mut masked = [0u8; 32];
    for i in 0..32 { masked[i] = msg[i] ^ key[i]; }
    ElGamalCiphertext { r_point, masked }
}

pub fn elgamal_decrypt(sk: &Scalar, ct: &ElGamalCiphertext) -> [u8; 32] {
    let shared = sk * ct.r_point;
    let key = kdf(&shared);
    let mut msg = [0u8; 32];
    for i in 0..32 { msg[i] = ct.masked[i] ^ key[i]; }
    msg
}

pub fn h1(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"H1-domain");
    hasher.update(input);
    hasher.finalize().into()
}

pub fn h2(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"H2-domain");
    hasher.update(input);
    hasher.finalize().into()
}

pub fn mac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut h = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC accepte n'importe quelle taille de clé");
    h.update(msg);
    h.finalize().into_bytes().into()
}

pub fn mac_verify(key: &[u8; 32], msg: &[u8], tag: &[u8; 32]) -> bool {
    let expected = mac(key, msg);
    use subtle::ConstantTimeEq;
    expected.ct_eq(tag).into()
}

pub fn ae_encrypt(key: &[u8; 32], seq: u64, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.encrypt(nonce, plaintext).expect("chiffrement échoue")
}

pub fn ae_decrypt(key: &[u8; 32], seq: u64, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "échec AEAD".to_string())
}

// Effectue un XOR entre deux tableaux de 32 octets
pub fn xor_32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}
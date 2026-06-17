//! Types des messages échangés entre Client, Firewall et Serveur.
//! Inclut la sérialisation manuelle des types de curve25519-dalek
//! (RistrettoPoint, Scalar) et ed25519-dalek (Signature) qui n'implémentent
//! pas Serialize/Deserialize nativement.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::Signature;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error as DeError;

use crate::crypto::ElGamalCiphertext;

// ---------------------------------------------------------------------------
// Helpers de sérialisation : RistrettoPoint ↔ [u8; 32]
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
// Helpers de sérialisation : Scalar ↔ [u8; 32]
// ---------------------------------------------------------------------------

fn ser_scalar<S: Serializer>(sc: &Scalar, s: S) -> Result<S::Ok, S::Error> {
    sc.to_bytes().serialize(s)
}

fn de_scalar<'de, D: Deserializer<'de>>(d: D) -> Result<Scalar, D::Error> {
    let bytes = <[u8; 32]>::deserialize(d)?;
    Ok(Scalar::from_bytes_mod_order(bytes))
}

// ---------------------------------------------------------------------------
// Helpers de sérialisation : Signature ↔ [u8; 64]
// ---------------------------------------------------------------------------

fn ser_sig<S: Serializer>(sig: &Signature, s: S) -> Result<S::Ok, S::Error> {
    sig.to_bytes().serialize(s)
}

fn de_sig<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
    let bytes = <[u8; 64]>::try_from(
        <Vec<u8>>::deserialize(d)?.as_slice()
    ).map_err(|_| D::Error::custom("signature doit faire 64 bytes"))?;
    Ok(Signature::from_bytes(&bytes))
}

// ---------------------------------------------------------------------------
// Helpers de sérialisation : VerifyingKey ↔ [u8; 32]
// ---------------------------------------------------------------------------

fn ser_vk<S: Serializer>(vk: &ed25519_dalek::VerifyingKey, s: S) -> Result<S::Ok, S::Error> {
    vk.to_bytes().serialize(s)
}

fn de_vk<'de, D: Deserializer<'de>>(d: D) -> Result<ed25519_dalek::VerifyingKey, D::Error> {
    let bytes = <[u8; 32]>::deserialize(d)?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|e| D::Error::custom(format!("VerifyingKey invalide : {}", e)))
}

// ===========================================================================
//  Messages du handshake (Fig. 3)
// ===========================================================================

/// Message 1 : Client -> Firewall  (X, C, e)
#[derive(Serialize, Deserialize)]
pub struct ClientInit {
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub big_x: RistrettoPoint,
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub big_c: RistrettoPoint,
    pub enc_c: ElGamalCiphertext,
}

/// Message 2 : Firewall -> Server  (X̃, C̃, ẽ)
#[derive(Serialize, Deserialize)]
pub struct FirewallToServer {
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub big_x_tilde: RistrettoPoint,
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub big_c_tilde: RistrettoPoint,
    pub enc_c_tilde: ElGamalCiphertext,
}

/// Message 3 : Server -> Firewall  (σ, Y, D, β1, β2)
#[derive(Serialize, Deserialize)]
pub struct ServerResponse {
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub big_y: RistrettoPoint,
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub big_d: RistrettoPoint,
    #[serde(serialize_with = "ser_scalar", deserialize_with = "de_scalar")]
    pub beta1: Scalar,
    #[serde(serialize_with = "ser_scalar", deserialize_with = "de_scalar")]
    pub beta2: Scalar,
    #[serde(serialize_with = "ser_sig", deserialize_with = "de_sig")]
    pub signature: Signature,
}

/// Message 4 : Firewall -> Client  (σ, Y, D, γ1, γ2)
#[derive(Serialize, Deserialize)]
pub struct FirewallToClient {
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub big_y: RistrettoPoint,
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub big_d: RistrettoPoint,
    #[serde(serialize_with = "ser_scalar", deserialize_with = "de_scalar")]
    pub gamma1: Scalar,
    #[serde(serialize_with = "ser_scalar", deserialize_with = "de_scalar")]
    pub gamma2: Scalar,
    #[serde(serialize_with = "ser_sig", deserialize_with = "de_sig")]
    pub signature: Signature,
}

// ===========================================================================
//  Messages de la couche record (Fig. 4)
// ===========================================================================

/// Triplet (r, s, t) — Client->Firewall ou Firewall->Server.
#[derive(Serialize, Deserialize)]
pub struct RecordMessage {
    pub r: [u8; 32],
    pub s: Vec<u8>,
    pub t: [u8; 32],
}

// ===========================================================================
//  Messages de bootstrap (échange de clés publiques au démarrage)
// ===========================================================================

/// Envoyé par le Server au Firewall à la connexion.
#[derive(Serialize, Deserialize)]
pub struct ServerHello {
    #[serde(serialize_with = "ser_vk", deserialize_with = "de_vk")]
    pub pk_server: ed25519_dalek::VerifyingKey,
}

/// Envoyé par le Firewall au Client : relai de pk_server + pk_fw.
#[derive(Serialize, Deserialize)]
pub struct FirewallHello {
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub pk_fw: RistrettoPoint,
    #[serde(serialize_with = "ser_vk", deserialize_with = "de_vk")]
    pub pk_server: ed25519_dalek::VerifyingKey,
}
/// Message direct Client -> Server (sans firewall, cf Fig. 2).
#[derive(Serialize, Deserialize)]
pub struct ClientInitDirect {
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub big_x: RistrettoPoint,
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub big_c: RistrettoPoint,
}

/// Reponse directe Server -> Client (sans firewall, cf Fig. 2).
#[derive(Serialize, Deserialize)]
pub struct ServerResponseDirect {
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub big_y: RistrettoPoint,
    #[serde(serialize_with = "ser_point", deserialize_with = "de_point")]
    pub big_d: RistrettoPoint,
    #[serde(serialize_with = "ser_scalar", deserialize_with = "de_scalar")]
    pub beta1: Scalar,
    #[serde(serialize_with = "ser_scalar", deserialize_with = "de_scalar")]
    pub beta2: Scalar,
    #[serde(serialize_with = "ser_sig", deserialize_with = "de_sig")]
    pub signature: Signature,
}

/// Message de la couche record en mode direct (sans firewall) :
/// AEAD simple avec kcs, pas de couche kcfs.
#[derive(Serialize, Deserialize)]
pub struct DirectRecord {
    pub seq: u64,
    pub ciphertext: Vec<u8>,
}
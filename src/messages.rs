use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::crypto::ElGamalCiphertext;

// =======================================================================
//  Messages du handshake (Fig. 3)
// =======================================================================

/// Message 1 : Client -> Firewall.
/// Correspond à (X, C, e) dans l'article.
#[derive(Serialize, Deserialize)]
pub struct ClientInit {
    pub big_x: RistrettoPoint, // X = g^x
    pub big_c: RistrettoPoint, // C = g^c
    pub enc_c: ElGamalCiphertext, // e = Enc_pkFW(c)
}

/// Message 2 : Firewall -> Server.
/// Correspond à (X̃, C̃, ẽ) dans l'article.
#[derive(Serialize, Deserialize)]
pub struct FirewallToServer {
    pub big_x_tilde: RistrettoPoint,
    pub big_c_tilde: RistrettoPoint,
    pub enc_c_tilde: ElGamalCiphertext,
}

/// Message 3 : Server -> Firewall.
/// Correspond à (sigma, Y, D, beta1, beta2) dans l'article.
#[derive(Serialize, Deserialize)]
pub struct ServerResponse {
    pub big_y: RistrettoPoint,
    pub big_d: RistrettoPoint,
    pub beta1: Scalar,
    pub beta2: Scalar,
    pub signature: Signature,
}

/// Message 4 : Firewall -> Client.
/// Correspond à (sigma, Y, D, gamma1, gamma2) dans l'article.
#[derive(Serialize, Deserialize)]
pub struct FirewallToClient {
    pub big_y: RistrettoPoint,
    pub big_d: RistrettoPoint,
    pub gamma1: Scalar,
    pub gamma2: Scalar,
    pub signature: Signature,
}

// =======================================================================
//  Messages de la couche record (Fig. 4)
// =======================================================================

/// Un message de la couche record : triplet (r, s, t).
/// Utilisé à la fois pour le message Client -> Firewall et Firewall -> Server
/// (avec des valeurs differentes (r,s,t) vs (r_tilde, s_tilde, t_tilde)).
#[derive(Serialize, Deserialize)]
pub struct RecordMessage {
    pub r: [u8; 32],
    pub s: Vec<u8>, // longueur variable car s = k1 XOR C, et |C| depend de |M|
    pub t: [u8; 32],
}

/// Envoye par le Server au Firewall a la connexion.
#[derive(Serialize, Deserialize)]
pub struct ServerHello {
    pub pk_server: ed25519_dalek::VerifyingKey,
}

/// Envoye par le Firewall au Client a la connexion : relai de pk_server + pk_fw.
#[derive(Serialize, Deserialize)]
pub struct FirewallHello {
    pub pk_fw: RistrettoPoint,
    pub pk_server: ed25519_dalek::VerifyingKey,
}
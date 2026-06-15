//! Structures de données représentant les messages échangés entre
//! le Client, le Pare-feu (Firewall) et le Serveur.
//!
//! Ces structures correspondent directement aux flèches du diagramme de
//! la Fig. 3 (handshake) et de la Fig. 4 (couche record) de l'article.
//! Elles sont déjà complètes : vous n'avez rien à modifier ici pour la
//! phase 1 (simulation locale, sans réseau).
//!
//! Phase 2 (réseau) : il faudra leur ajouter `#[derive(Serialize, Deserialize)]`
//! (crate serde) pour pouvoir les envoyer sur le réseau. On en reparlera
//! une fois la phase 1 terminée.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::Signature;

use crate::crypto::ElGamalCiphertext;

// =======================================================================
//  Messages du handshake (Fig. 3)
// =======================================================================

/// Message 1 : Client -> Firewall.
/// Correspond à (X, C, e) dans l'article.
pub struct ClientInit {
    pub big_x: RistrettoPoint, // X = g^x
    pub big_c: RistrettoPoint, // C = g^c
    pub enc_c: ElGamalCiphertext, // e = Enc_pkFW(c)
}

/// Message 2 : Firewall -> Server.
/// Correspond à (X̃, C̃, ẽ) dans l'article.
pub struct FirewallToServer {
    pub big_x_tilde: RistrettoPoint,
    pub big_c_tilde: RistrettoPoint,
    pub enc_c_tilde: ElGamalCiphertext,
}

/// Message 3 : Server -> Firewall.
/// Correspond à (sigma, Y, D, beta1, beta2) dans l'article.
pub struct ServerResponse {
    pub big_y: RistrettoPoint,
    pub big_d: RistrettoPoint,
    pub beta1: Scalar,
    pub beta2: Scalar,
    pub signature: Signature,
}

/// Message 4 : Firewall -> Client.
/// Correspond à (sigma, Y, D, gamma1, gamma2) dans l'article.
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
pub struct RecordMessage {
    pub r: [u8; 32],
    pub s: Vec<u8>, // longueur variable car s = k1 XOR C, et |C| depend de |M|
    pub t: [u8; 32],
}

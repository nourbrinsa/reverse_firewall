//! Le Client : initiateur du handshake (cf Fig. 3, colonne de gauche).
//!
//! A la fin du handshake, le client doit avoir calcule kcs et kcfs,
//! qui doivent etre identiques aux valeurs calculees par le Serveur
//! (et kcfs doit aussi etre identique a celle calculee par le Firewall).

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Verifier, VerifyingKey};
use rand::RngCore;

use crate::crypto;
use crate::messages::{ClientInit, FirewallToClient};

pub struct Client {
    /// Secrets ephemeres x et c (cf "x, c <- Zp" dans Fig. 3).
    x: Scalar,
    c: Scalar,

    /// Cle publique du pare-feu, utilisee pour Enc_pkFW.
    pk_fw: RistrettoPoint,

    /// Cle publique de signature du serveur, pour verifier sigma.
    pk_server: VerifyingKey,

    /// Cles de session, calculees a la fin du handshake (Some apres `finalize`).
    pub kcs: Option<[u8; 32]>,
    pub kcfs: Option<[u8; 32]>,
}

impl Client {
    /// Cree un nouveau client avec des secrets x, c frais.
    ///
    /// TODO (etape 1 de Fig. 3) :
    ///   - tirer x et c aleatoirement avec crypto::random_scalar(rng)
    ///   - retourner un Client avec ces secrets, kcs = None, kcfs = None
    pub fn new(pk_fw: RistrettoPoint, pk_server: VerifyingKey, rng: &mut impl RngCore) -> Self {
        todo!("Generer x et c aleatoirement (crypto::random_scalar), construire le Client")
    }

    /// Construit le premier message envoye au Firewall : (X, C, e).
    ///
    /// Reference : Fig. 3, premiere fleche "Client -> Firewall".
    ///
    /// TODO :
    ///   1. Calculer X = g^x  -> crypto::base_point(&self.x)
    ///   2. Calculer C = g^c  -> crypto::base_point(&self.c)
    ///   3. Chiffrer c pour le firewall :
    ///        e = crypto::elgamal_encrypt(&self.pk_fw, &self.c.to_bytes(), rng)
    ///   4. Retourner ClientInit { big_x: X, big_c: C, enc_c: e }
    pub fn init_message(&self, rng: &mut impl RngCore) -> ClientInit {
        todo!("Construire (X, C, e)")
    }

    /// Traite la reponse finale du Firewall : (sigma, Y, D, gamma1, gamma2).
    ///
    /// Reference : Fig. 3, derniere fleche "Firewall -> Client".
    ///
    /// TODO, doit :
    ///   1. Reconstruire le transcript signe : (Y, D, X^gamma1, C^gamma2)
    ///      Note : X^gamma1 = crypto::base_point(&(self.x * msg.gamma1))
    ///             C^gamma2 = crypto::base_point(&(self.c * msg.gamma2))
    ///   2. Verifier la signature avec self.pk_server.verify(&transcript_bytes, &msg.signature)
    ///      -> crypto::concat_points(&[&msg.big_y, &msg.big_d, &x_gamma1, &c_gamma2])
    ///   3. Si la signature est invalide : retourner Err(...) (abort, cf Fig. 3 "Else: abort")
    ///   4. Si valide :
    ///        - kcs_point  = Y^(x*gamma1)  = (self.x * msg.gamma1) * msg.big_y
    ///        - kcfs_point = D^(c*gamma2)  = (self.c * msg.gamma2) * msg.big_d
    ///        - self.kcs  = Some(crypto::kdf(&kcs_point))
    ///        - self.kcfs = Some(crypto::kdf(&kcfs_point))
    pub fn finalize(&mut self, msg: FirewallToClient) -> Result<(), String> {
        todo!("Verifier sigma puis calculer kcs et kcfs")
    }
}

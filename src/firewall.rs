//! Le Pare-feu inverse (Reverse Firewall) : situe entre le Client et le
//! Serveur. Il "repare" le handshake en rerandomisant les elements
//! Diffie-Hellman (cf Fig. 3, colonne centrale), puis protege la couche
//! record (cf Fig. 4).
//!
//! Notes importantes :
//!   - Le firewall ne connait JAMAIS kcs (confidentialite de bout en bout).
//!   - Le firewall calcule kcfs, identique a celle du client et du serveur.
//!   - L'etat ephemere (alpha1, alpha2, c) doit etre conserve entre
//!     `process_client_init` et `process_server_response` : on stocke ca
//!     dans une struct `FirewallSession` (une par poignee de main en cours).

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Verifier, VerifyingKey};
use rand::RngCore;

use crate::crypto;
use crate::messages::{ClientInit, FirewallToClient, FirewallToServer, RecordMessage, ServerResponse};

/// Cles a long terme du firewall (generees une seule fois au lancement).
pub struct Firewall {
    sk_fw: Scalar,
    pub pk_fw: RistrettoPoint,

    /// Cle publique du serveur, pour verifier sigma avant de calculer gamma.
    pk_server: VerifyingKey,
}

/// Etat ephemere d'une session de handshake en cours, entre les deux
/// messages traites par le firewall.
pub struct FirewallSession {
    alpha1: Scalar,
    alpha2: Scalar,
    /// c, dechiffre depuis e lors de process_client_init.
    c: Scalar,
    /// X et C originaux du client (utiles pour les verifications de groupe
    /// et pour reconstruire le transcript signe).
    big_x: RistrettoPoint,
    big_c: RistrettoPoint,

    /// kcfs, calcule a la fin de process_server_response.
    pub kcfs: Option<[u8; 32]>,
}

impl Firewall {
    /// TODO (setup, cf section 3.1 "Setup") :
    ///   - tirer sk_fw aleatoirement (crypto::random_scalar)
    ///   - pk_fw = crypto::base_point(&sk_fw)
    pub fn new(pk_server: VerifyingKey, rng: &mut impl RngCore) -> Self {
        todo!("Generer (sk_fw, pk_fw)")
    }

    /// Traite le message (X, C, e) recu du client.
    ///
    /// Reference : Fig. 3, etape du Firewall apres reception de (X,C,e).
    ///
    /// TODO, doit :
    ///   1. Dechiffrer e avec sk_fw -> c_bytes = crypto::elgamal_decrypt(&self.sk_fw, &msg.enc_c)
    ///      puis c = Scalar::from_bytes_mod_order(c_bytes)
    ///   2. Verification de securite (cf section 3.2) :
    ///        si crypto::base_point(&c) != msg.big_c : abort (le client a triche)
    ///   3. Tirer alpha1, alpha2 aleatoirement
    ///   4. Calculer X_tilde = alpha1 * msg.big_x,  C_tilde = alpha2 * msg.big_c
    ///   5. Chiffrer c_tilde = c * alpha2 pour le firewall :
    ///        enc_c_tilde = crypto::elgamal_encrypt(&self.pk_fw, &(c*alpha2).to_bytes(), rng)
    ///   6. Retourner (FirewallToServer { big_x_tilde: X_tilde, big_c_tilde: C_tilde, enc_c_tilde },
    ///                 FirewallSession { alpha1, alpha2, c, big_x: msg.big_x, big_c: msg.big_c, kcfs: None })
    pub fn process_client_init(
        &self,
        msg: ClientInit,
        rng: &mut impl RngCore,
    ) -> Result<(FirewallToServer, FirewallSession), String> {
        todo!("Dechiffrer c, verifier, rerandomiser (alpha1, alpha2), reconstruire e_tilde")
    }

    /// Traite la reponse (sigma, Y, D, beta1, beta2) recue du serveur.
    ///
    /// Reference : Fig. 3, etape du Firewall apres reception de la reponse serveur.
    ///
    /// TODO, doit :
    ///   1. Calculer gamma1 = session.alpha1 * msg.beta1,  gamma2 = session.alpha2 * msg.beta2
    ///   2. Reconstruire le transcript signe : (Y, D, X^gamma1, C^gamma2)
    ///        ou X = session.big_x (le X *original* du client, pas X_tilde !)
    ///        et C = session.big_c
    ///      X^gamma1 et C^gamma2 se calculent par multiplication scalaire d'un point :
    ///        x_gamma1 = gamma1 * session.big_x
    ///        c_gamma2 = gamma2 * session.big_c
    ///   3. Verifier la signature self.pk_server.verify(&transcript_bytes, &msg.signature)
    ///      Si invalide : abort.
    ///   4. Calculer kcfs_point = D^(c*gamma2) = (session.c * gamma2) * msg.big_d
    ///      kcfs = crypto::kdf(&kcfs_point)
    ///   5. Retourner FirewallToClient { big_y: msg.big_y, big_d: msg.big_d, gamma1, gamma2, signature: msg.signature }
    ///      et mettre a jour session.kcfs = Some(kcfs)
    pub fn process_server_response(
        &self,
        msg: ServerResponse,
        session: &mut FirewallSession,
    ) -> Result<FirewallToClient, String> {
        todo!("Calculer gamma1, gamma2, verifier sigma, calculer kcfs")
    }

    /// Traite un message de la couche record envoye par le client : (r, s, t).
    ///
    /// Reference : Fig. 4, etape du Firewall.
    ///
    /// TODO, doit :
    ///   1. k1 = crypto::h1(&[r, kcfs].concat()), k2 = crypto::h2(&[r, kcfs].concat())
    ///   2. Verifier que t == crypto::mac(&k2, &[r, s].concat())  (sinon abort)
    ///   3. Recuperer C = crypto::xor32(&k1, &s_as_32_bytes)
    ///      -- pour debuter, supposez que s fait exactement 32 octets
    ///         (un seul bloc de message). Vous generaliserez ensuite a des
    ///         messages plus longs avec un flux derive de kcfs.
    ///   4. Tirer r_tilde aleatoirement (32 octets aleatoires, rng.fill_bytes)
    ///   5. k1_tilde = crypto::h1(&[r_tilde, kcfs].concat()), k2_tilde = crypto::h2(&[r_tilde, kcfs].concat())
    ///   6. s_tilde = crypto::xor32(&k1_tilde, &C)
    ///   7. t_tilde = crypto::mac(&k2_tilde, &[r_tilde, s_tilde].concat())
    ///   8. Retourner RecordMessage { r: r_tilde, s: s_tilde.to_vec(), t: t_tilde }
    pub fn process_record_message(
        &self,
        msg: RecordMessage,
        kcfs: &[u8; 32],
        rng: &mut impl RngCore,
    ) -> Result<RecordMessage, String> {
        todo!("Rerandomiser (r,s,t) -> (r_tilde, s_tilde, t_tilde) en passant par kcfs")
    }
}

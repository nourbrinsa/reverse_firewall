//! Le Serveur : seule entite authentifiee du protocole (signatures, cf Fig. 3).
//!
//! Le serveur ne voit jamais X et C directement : il recoit les versions
//! rerandomisees (X_tilde, C_tilde, e_tilde) envoyees par le firewall. Dans
//! ce prototype (un seul firewall), e_tilde n'est pas utilise par le
//! serveur : il sert uniquement pour les chaines de plusieurs firewalls
//! (Annexe E de l'article), hors scope ici.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;

use crate::crypto;
use crate::messages::{FirewallToServer, RecordMessage, ServerResponse};

pub struct Server {
    sk: SigningKey,
    pub pk: VerifyingKey,

    /// Cles de session, calculees apres process_firewall_init.
    pub kcs: Option<[u8; 32]>,
    pub kcfs: Option<[u8; 32]>,
}

impl Server {
    /// TODO (setup) :
    ///   - generer une paire de cles ed25519 : SigningKey::generate(rng)
    ///     (note : SigningKey::generate attend un &mut R ou R: CryptoRng + RngCore)
    ///   - pk = sk.verifying_key()
    pub fn new(rng: &mut impl RngCore) -> Self {
        todo!("Generer la paire de cles de signature (sk, pk)")
    }

    /// Traite le message (X_tilde, C_tilde, e_tilde) recu du firewall et
    /// produit la reponse signee.
    ///
    /// Reference : Fig. 3, etape du Serveur.
    ///
    /// TODO, doit :
    ///   1. Tirer y, d, beta1, beta2 aleatoirement (crypto::random_scalar)
    ///   2. Y = crypto::base_point(&y),  D = crypto::base_point(&d)
    ///   3. Calculer X_tilde^beta1 = beta1 * msg.big_x_tilde
    ///             et C_tilde^beta2 = beta2 * msg.big_c_tilde
    ///      (multiplication scalaire d'un RistrettoPoint : `scalar * point`)
    ///   4. transcript = crypto::concat_points(&[&Y, &D, &x_tilde_beta1, &c_tilde_beta2])
    ///   5. sigma = self.sk.sign(&transcript)   (trait `Signer`, deja importe)
    ///   6. Calculer les cles de session :
    ///        kcs_point  = (y * beta1) * msg.big_x_tilde      // = X_tilde^(y*beta1)
    ///        kcfs_point = (d * beta2) * msg.big_c_tilde      // = C_tilde^(d*beta2)
    ///      self.kcs  = Some(crypto::kdf(&kcs_point))
    ///      self.kcfs = Some(crypto::kdf(&kcfs_point))
    ///   7. Retourner ServerResponse { big_y: Y, big_d: D, beta1, beta2, signature: sigma }
    pub fn process_firewall_init(
        &mut self,
        msg: FirewallToServer,
        rng: &mut impl RngCore,
    ) -> ServerResponse {
        todo!("Choisir y,d,beta1,beta2, signer le transcript, calculer kcs et kcfs")
    }

    /// Traite un message de la couche record recu du firewall : (r_tilde, s_tilde, t_tilde).
    ///
    /// Reference : Fig. 4, derniere etape (cote Serveur).
    ///
    /// TODO, doit :
    ///   1. kcfs = self.kcfs.unwrap() (deja calcule lors du handshake)
    ///   2. k1_tilde = crypto::h1(&[r_tilde, kcfs].concat()), k2_tilde = crypto::h2(&[r_tilde, kcfs].concat())
    ///   3. Verifier t_tilde == crypto::mac(&k2_tilde, &[r_tilde, s_tilde].concat())
    ///      -> sinon Err("MAC invalide")
    ///   4. C = crypto::xor32(&k1_tilde, &s_tilde_as_32_bytes)
    ///   5. M = crypto::ae_decrypt(&self.kcs.unwrap(), seq, &C)?
    ///   6. Retourner M
    pub fn process_record_message(&mut self, msg: RecordMessage, seq: u64) -> Result<Vec<u8>, String> {
        todo!("Verifier t_tilde, recuperer C, dechiffrer avec kcs")
    }
}

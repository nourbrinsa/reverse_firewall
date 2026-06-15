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
        // 32 octets aléatoires à utiliser comme clé secrète
        let mut bytes = [0u8; 32];
        rng.fill_bytes(bytes.as_mut_slice());

        // Construction de la clé secrète ed25519 à partir de ces octets
        let sk = SigningKey::from_bytes(&bytes);

        // Clé publique dérivée depuis sk
        let pk = sk.verifying_key();

        // Construction et retour du struct Server
        // kcs et kcfs sont None tant que le handshake n'est pas fini
        Server {
            sk,
            pk,
            kcs: None,
            kcfs: None,
        }
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
        // 1. y, d, beta1, beta2 aléatoires
        let y = crypto::random_scalar(rng);
        let d = crypto::random_scalar(rng);
        let beta1 = crypto::random_scalar(rng);
        let beta2 = crypto::random_scalar(rng);

        // 2. Y = g^y, D = g^d
        let big_y = crypto::base_point(&y);
        let big_d = crypto::base_point(&d);

        // 3. X_tilde^beta1 et C_tilde^beta2
        let x_tilde_beta1 = beta1 * msg.big_x_tilde;
        let c_tilde_beta2 = beta2 * msg.big_c_tilde;

        // 4. Construire le transcript (Y, D, X_tilde^beta1, C_tilde^beta2)
        let transcript = crypto::concat_points([&big_y, &big_d, &x_tilde_beta1, &c_tilde_beta2].as_slice());

        // 5. Signer le transcript
        let signature = self.sk.sign(&transcript);

        // 6. Calculer les clés de session
        // kcs = X_tilde^(y * beta1)
        // kcfs = C_tilde^(d * beta2)
        let kcs_point = (y * beta1) * msg.big_x_tilde;
        let kcfs_point = (d * beta2) * msg.big_c_tilde;

        self.kcs = Some(crypto::kdf(&kcs_point));
        self.kcfs = Some(crypto::kdf(&kcfs_point));

        // 7. Renvoyer la réponse (sigma, Y, D, beta1, beta2)
        ServerResponse {
            signature,
            big_y,
            big_d,
            beta1,
            beta2,
        }
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
        let kcs = self.kcs.unwrap();
        let kcfs = self.kcfs.unwrap();

        // 1. Concaténer r_tilde à kcfs, dériver k1_tilde et k2_tilde depuis r_tilde et kcfs,
        let mut r_kcfs = msg.r.to_vec();
        r_kcfs.extend_from_slice(&kcfs);

        let k1_tilde = crypto::h1(&r_kcfs);
        let k2_tilde = crypto::h2(&r_kcfs);

        // 2. Vérifier le MAC (t_tilde == MAC_k2(r_tilde || s_tilde))
        let mut mac_input = msg.r.to_vec();
        mac_input.extend_from_slice(&msg.s);

        if !crypto::mac_verify(&k2_tilde, &mac_input, &msg.t) {
            return Err("MAC Invalide : message rejeté".to_string());
        }

        // 3. Retrouver C = k1_tilde XOR s_tilde (on suppose que s fait exactement 32 octets)
        let s32: [u8; 32] = msg.s.as_slice().try_into().map_err(|_| "se ne fait pas 32 octets".to_string())?;
        let c_bytes = crypto::xor32(&k1_tilde, &s32);

        // 4. Déchiffrer C avec kcs pour obtenir le message en clair M
        let m = crypto::ae_decrypt(&kcs, seq, &c_bytes)?;

        Ok(m)
    }
}
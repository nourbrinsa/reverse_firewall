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
        let sk_fw = crypto::random_scalar(rng);
        let pk_fw = crypto::base_point(&sk_fw);
        Firewall {
            sk_fw,
            pk_fw,
            pk_server,
        }
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
        // 1. Dechiffrer e avec sk_fw
        let c_bytes = crypto::elgamal_decrypt(&self.sk_fw, &msg.enc_c);
        let c = Scalar::from_bytes_mod_order(c_bytes);

        // 2. Verification de securite : verifier que g^c == C
        if crypto::base_point(&c) != msg.big_c {
            return Err("Erreur de verification du client".to_string());
        }

        // 3. Tirer alpha1, alpha2 aleatoirement
        let alpha1 = crypto::random_scalar(rng);
        let alpha2 = crypto::random_scalar(rng);

        // 4. Calculer X_tilde et C_tilde
        let big_x_tilde = alpha1 * msg.big_x;
        let big_c_tilde = alpha2 * msg.big_c;

        // 5. Chiffrer c_tilde = c * alpha2
        let c_tilde_scalar = c * alpha2;
        let enc_c_tilde = crypto::elgamal_encrypt(&self.pk_fw, &c_tilde_scalar.to_bytes(), rng);

        // 6. Construire les reponses
        let fw_to_server = FirewallToServer {
            big_x_tilde,
            big_c_tilde,
            enc_c_tilde,
        };

        let fw_session = FirewallSession {
            alpha1,
            alpha2,
            c,
            big_x: msg.big_x,
            big_c: msg.big_c,
            kcfs: None,
        };

        Ok((fw_to_server, fw_session))
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
        // 1. Calculer gamma1 et gamma2
        let gamma1 = session.alpha1 * msg.beta1;
        let gamma2 = session.alpha2 * msg.beta2;

        // 2. Reconstruire le transcript signe
        let x_gamma1 = gamma1 * session.big_x;
        let c_gamma2 = gamma2 * session.big_c;
        let transcript_bytes = crypto::concat_points(&[&msg.big_y, &msg.big_d, &x_gamma1, &c_gamma2]);

        // 3. Verifier la signature
        self.pk_server
            .verify(&transcript_bytes, &msg.signature)
            .map_err(|_| "Echec de la verification de la signature serveur".to_string())?;

        // 4. Calculer kcfs
        let kcfs_point = (session.c * gamma2) * msg.big_d;
        let kcfs = crypto::kdf(&kcfs_point);

        // 5. Mettre a jour la session et retourner le message
        session.kcfs = Some(kcfs);

        Ok(FirewallToClient {
            big_y: msg.big_y,
            big_d: msg.big_d,
            gamma1,
            gamma2,
            signature: msg.signature,
        })
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
        // 1. Calculer k1 et k2
        let mut input = Vec::new();
        input.extend_from_slice(&msg.r);
        input.extend_from_slice(kcfs);

        let k1 = crypto::h1(&input);
        let k2 = crypto::h2(&input);

        // 2. Verifier le MAC
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&msg.r);
        mac_input.extend_from_slice(&msg.s);

        if !crypto::mac_verify(&k2, &mac_input, &msg.t) {
            return Err("Echec de la verification du MAC".to_string());
        }

        // 3. Recuperer C = k1 XOR s
        // On suppose que s fait exactement 32 octets
        if msg.s.len() != 32 {
            return Err("Message s doit faire exactement 32 octets".to_string());
        }

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&msg.s);
        let c = crypto::xor32(&k1, &s_bytes);

        // 4. Tirer r_tilde aleatoirement
        let mut r_tilde = [0u8; 32];
        rng.fill_bytes(&mut r_tilde);

        // 5. Calculer k1_tilde et k2_tilde
        let mut input_tilde = Vec::new();
        input_tilde.extend_from_slice(&r_tilde);
        input_tilde.extend_from_slice(kcfs);

        let k1_tilde = crypto::h1(&input_tilde);
        let k2_tilde = crypto::h2(&input_tilde);

        // 6. Calculer s_tilde = k1_tilde XOR C
        let s_tilde = crypto::xor32(&k1_tilde, &c);

        // 7. Calculer t_tilde
        let mut mac_input_tilde = Vec::new();
        mac_input_tilde.extend_from_slice(&r_tilde);
        mac_input_tilde.extend_from_slice(&s_tilde);

        let t_tilde = crypto::mac(&k2_tilde, &mac_input_tilde);

        // 8. Retourner le message rerandomise
        Ok(RecordMessage {
            r: r_tilde,
            s: s_tilde.to_vec(),
            t: t_tilde,
        })
    }
}

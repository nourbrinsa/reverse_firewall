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
    /// Setup (cf section 3.1) : genere la paire de cles ElGamal du firewall.
    pub fn new(pk_server: VerifyingKey, rng: &mut impl RngCore) -> Self {
        let sk_fw = crypto::random_scalar(rng);
        let pk_fw = crypto::base_point(&sk_fw);
        Firewall { sk_fw, pk_fw, pk_server }
    }

    /// Traite le message (X, C, e) recu du client.
    ///
    /// Reference : Fig. 3, etape du Firewall apres reception de (X,C,e).
    pub fn process_client_init(
        &self,
        msg: ClientInit,
        rng: &mut impl RngCore,
    ) -> Result<(FirewallToServer, FirewallSession), String> {
        // 1. Dechiffrer e pour recuperer c.
        let c_bytes = crypto::elgamal_decrypt(&self.sk_fw, &msg.enc_c);
        let c = Scalar::from_bytes_mod_order(c_bytes);

        // 2. Verification de securite (cf section 3.2) : C doit etre
        //    coherent avec le c dechiffre. Si ce n'est pas le cas, le
        //    client a triche (ou e est corrompu) -> on abandonne.
        if crypto::base_point(&c) != msg.big_c {
            return Err("incoherence detectee : g^c != C".to_string());
        }

        // 3. Tirer les facteurs de rerandomisation.
        let alpha1 = crypto::random_scalar(rng);
        let alpha2 = crypto::random_scalar(rng);

        // 4. Rerandomiser X et C.
        //    X_tilde = X^alpha1 = alpha1 * X (notation additive)
        //    C_tilde = C^alpha2 = alpha2 * C
        let big_x_tilde = alpha1 * msg.big_x;
        let big_c_tilde = alpha2 * msg.big_c;

        // 5. Rechiffrer c * alpha2 pour le firewall (transparence du format,
        //    cf discussion sur e_tilde).
        let c_tilde = c * alpha2;
        let enc_c_tilde = crypto::elgamal_encrypt(&self.pk_fw, &c_tilde.to_bytes(), rng);

        let fw_to_server = FirewallToServer {
            big_x_tilde,
            big_c_tilde,
            enc_c_tilde,
        };

        // 6. On garde alpha1, alpha2, c et les X/C originaux pour
        //    process_server_response.
        let session = FirewallSession {
            alpha1,
            alpha2,
            c,
            big_x: msg.big_x,
            big_c: msg.big_c,
            kcfs: None,
        };

        Ok((fw_to_server, session))
    }

    /// Traite la reponse (sigma, Y, D, beta1, beta2) recue du serveur.
    ///
    /// Reference : Fig. 3, etape du Firewall apres reception de la reponse serveur.
    pub fn process_server_response(
        &self,
        msg: ServerResponse,
        session: &mut FirewallSession,
    ) -> Result<FirewallToClient, String> {
        // 1. gamma1 = alpha1 * beta1, gamma2 = alpha2 * beta2
        let gamma1 = session.alpha1 * msg.beta1;
        let gamma2 = session.alpha2 * msg.beta2;

        // 2. Reconstruire le transcript signe (Y, D, X^gamma1, C^gamma2),
        //    ou X et C sont les valeurs ORIGINALES du client (pas X_tilde/C_tilde).
        //    Rappel : X^gamma1 = X_tilde^beta1 (c'est ce que le serveur a
        //    effectivement signe), donc on peut le recalculer ainsi.
        let x_gamma1 = gamma1 * session.big_x;
        let c_gamma2 = gamma2 * session.big_c;
        let transcript = crypto::concat_points(&[&msg.big_y, &msg.big_d, &x_gamma1, &c_gamma2]);

        // 3. Verifier la signature du serveur.
        self.pk_server
            .verify(&transcript, &msg.signature)
            .map_err(|_| "signature du serveur invalide".to_string())?;

        // 4. Calculer kcfs = D^(c*gamma2).
        let kcfs_point = (session.c * gamma2) * msg.big_d;
        session.kcfs = Some(crypto::kdf(&kcfs_point));

        // 5. Transmettre (sigma, Y, D, gamma1, gamma2) au client.
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
    pub fn process_record_message(
        &self,
        msg: RecordMessage,
        kcfs: &[u8; 32],
        rng: &mut impl RngCore,
    ) -> Result<RecordMessage, String> {
        // 1. Recalculer k1, k2 a partir de r recu.
        let k1 = crypto::h1(&[msg.r.as_slice(), kcfs.as_slice()].concat());
        let k2 = crypto::h2(&[msg.r.as_slice(), kcfs.as_slice()].concat());

        // 2. Verifier le MAC recu.
        if !crypto::mac_verify(&k2, &[msg.r.as_slice(), msg.s.as_slice()].concat(), &msg.t) {
            return Err("MAC invalide a la reception".to_string());
        }

        // 3. Recuperer C = k1 XOR s (XOR cyclique sur k1 de 32 octets,
        //    fonctionne pour toute taille de s).
        let big_c: Vec<u8> = msg.s
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ k1[i % 32])
            .collect();

        // 4. Tirer un nouveau nonce r_tilde, frais et aleatoire.
        let mut r_tilde = [0u8; 32];
        rng.fill_bytes(&mut r_tilde);

        // 5. Recalculer k1_tilde, k2_tilde a partir de r_tilde.
        let k1_tilde = crypto::h1(&[r_tilde.as_slice(), kcfs.as_slice()].concat());
        let k2_tilde = crypto::h2(&[r_tilde.as_slice(), kcfs.as_slice()].concat());

        // 6. Re-masquer C avec k1_tilde.
        let s_tilde: Vec<u8> = big_c
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ k1_tilde[i % 32])
            .collect();

        // 7. Recalculer le MAC sur (r_tilde, s_tilde).
        let t_tilde = crypto::mac(&k2_tilde, &[r_tilde.as_slice(), s_tilde.as_slice()].concat());

        // 8. Transmettre (r_tilde, s_tilde, t_tilde) au serveur.
        Ok(RecordMessage {
            r: r_tilde,
            s: s_tilde.to_vec(),
            t: t_tilde,
        })
    }
}


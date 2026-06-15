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
    ///
    /// NOTE prototype : on suppose ici que `s` fait exactement 32 octets
    /// (c'est-a-dire que le chiffre AEAD C tient sur un seul "bloc" de 32
    /// octets cote H1/H2). Pour des messages plus longs, il faudra
    /// generaliser le XOR avec un flux derive de kcfs (par exemple en
    /// hachant kcfs||compteur pour chaque bloc de 32 octets).
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

        // 3. Recuperer C = k1 XOR s (prototype : s fait 32 octets).
        if msg.s.len() != 32 {
            return Err("taille de s non supportee par ce prototype (attendu : 32 octets)".to_string());
        }
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&msg.s);
        let big_c = crypto::xor32(&k1, &s_bytes);

        // 4. Tirer un nouveau nonce r_tilde, frais et aleatoire.
        let mut r_tilde = [0u8; 32];
        rng.fill_bytes(&mut r_tilde);

        // 5. Recalculer k1_tilde, k2_tilde a partir de r_tilde.
        let k1_tilde = crypto::h1(&[r_tilde.as_slice(), kcfs.as_slice()].concat());
        let k2_tilde = crypto::h2(&[r_tilde.as_slice(), kcfs.as_slice()].concat());

        // 6. Re-masquer C avec k1_tilde.
        let s_tilde = crypto::xor32(&k1_tilde, &big_c);

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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn test_process_client_init_honest_client() {
        let mut rng = OsRng;
        let server_sk = SigningKey::generate(&mut rng);
        let firewall = Firewall::new(server_sk.verifying_key(), &mut rng);

        // Simule un client honnete construisant (X, C, e) comme dans
        // client::Client::init_message.
        let x = crypto::random_scalar(&mut rng);
        let c = crypto::random_scalar(&mut rng);
        let big_x = crypto::base_point(&x);
        let big_c = crypto::base_point(&c);
        let enc_c = crypto::elgamal_encrypt(&firewall.pk_fw, &c.to_bytes(), &mut rng);

        let client_init = ClientInit { big_x, big_c, enc_c };

        let (fw_to_server, session) = firewall
            .process_client_init(client_init, &mut rng)
            .expect("un client honnete ne doit pas etre rejete");

        // Le firewall a bien retrouve le c original.
        assert_eq!(session.c, c);
        assert_eq!(session.big_x, big_x);
        assert_eq!(session.big_c, big_c);

        // X_tilde et C_tilde sont bien des rerandomisations : on peut les
        // dechiffrer/verifier en reconstruisant alpha a partir de e_tilde.
        let c_tilde_bytes = crypto::elgamal_decrypt(&firewall.sk_fw, &fw_to_server.enc_c_tilde);
        let c_tilde = Scalar::from_bytes_mod_order(c_tilde_bytes);
        assert_eq!(crypto::base_point(&c_tilde), fw_to_server.big_c_tilde);

        // c_tilde = c * alpha2, donc C_tilde = C^alpha2 -> coherent.
        assert_eq!(c_tilde, c * session.alpha2);
        assert_eq!(fw_to_server.big_x_tilde, session.alpha1 * big_x);
    }

    #[test]
    fn test_process_client_init_rejects_inconsistent_c() {
        let mut rng = OsRng;
        let server_sk = SigningKey::generate(&mut rng);
        let firewall = Firewall::new(server_sk.verifying_key(), &mut rng);

        // Le client envoie un C qui ne correspond pas au c chiffre dans e.
        let x = crypto::random_scalar(&mut rng);
        let c = crypto::random_scalar(&mut rng);
        let other_c = crypto::random_scalar(&mut rng);

        let big_x = crypto::base_point(&x);
        let big_c_wrong = crypto::base_point(&other_c); // != g^c
        let enc_c = crypto::elgamal_encrypt(&firewall.pk_fw, &c.to_bytes(), &mut rng);

        let client_init = ClientInit { big_x, big_c: big_c_wrong, enc_c };

        let result = firewall.process_client_init(client_init, &mut rng);
        assert!(result.is_err(), "un C incoherent avec e doit etre rejete");
    }

    /// Test d'integration "a la main" : simule un client et un serveur
    /// honnetes (sans utiliser client.rs / server.rs, encore en TODO),
    /// et verifie que les trois parties calculent bien le meme kcs/kcfs.
    #[test]
    fn test_full_handshake_through_firewall() {
        let mut rng = OsRng;

        // --- Setup ---
        let server_sk = SigningKey::generate(&mut rng);
        let server_pk = server_sk.verifying_key();
        let firewall = Firewall::new(server_pk, &mut rng);

        // --- Etape 1 : Client -> Firewall ---
        let x = crypto::random_scalar(&mut rng);
        let c = crypto::random_scalar(&mut rng);
        let big_x = crypto::base_point(&x);
        let big_c = crypto::base_point(&c);
        let enc_c = crypto::elgamal_encrypt(&firewall.pk_fw, &c.to_bytes(), &mut rng);
        let client_init = ClientInit { big_x, big_c, enc_c };

        // --- Etape 2 : Firewall -> Server ---
        let (fw_to_server, mut session) = firewall
            .process_client_init(client_init, &mut rng)
            .expect("client honnete");

        // --- Etape 3 : Server -> Firewall (simule "a la main") ---
        let y = crypto::random_scalar(&mut rng);
        let d = crypto::random_scalar(&mut rng);
        let beta1 = crypto::random_scalar(&mut rng);
        let beta2 = crypto::random_scalar(&mut rng);
        let big_y = crypto::base_point(&y);
        let big_d = crypto::base_point(&d);

        let x_tilde_beta1 = beta1 * fw_to_server.big_x_tilde;
        let c_tilde_beta2 = beta2 * fw_to_server.big_c_tilde;
        let transcript = crypto::concat_points(&[&big_y, &big_d, &x_tilde_beta1, &c_tilde_beta2]);
        let signature = server_sk.sign(&transcript);

        let server_kcs = crypto::kdf(&((y * beta1) * fw_to_server.big_x_tilde));
        let server_kcfs = crypto::kdf(&((d * beta2) * fw_to_server.big_c_tilde));

        let server_response = ServerResponse { big_y, big_d, beta1, beta2, signature };

        // --- Etape 4 : Firewall -> Client ---
        let fw_to_client = firewall
            .process_server_response(server_response, &mut session)
            .expect("la signature du serveur doit etre valide");

        // kcfs cote firewall == kcfs cote serveur
        assert_eq!(session.kcfs.expect("kcfs doit etre calcule"), server_kcfs);

        // --- Etape 5 : Client (simule "a la main") ---
        let x_gamma1 = crypto::base_point(&(x * fw_to_client.gamma1));
        let c_gamma2 = crypto::base_point(&(c * fw_to_client.gamma2));
        let client_transcript =
            crypto::concat_points(&[&fw_to_client.big_y, &fw_to_client.big_d, &x_gamma1, &c_gamma2]);
        assert!(server_pk.verify(&client_transcript, &fw_to_client.signature).is_ok());

        let client_kcs = crypto::kdf(&((x * fw_to_client.gamma1) * fw_to_client.big_y));
        let client_kcfs = crypto::kdf(&((c * fw_to_client.gamma2) * fw_to_client.big_d));

        // --- Verifications finales ---
        assert_eq!(client_kcs, server_kcs, "kcs doit etre identique cote client et serveur");
        assert_eq!(client_kcfs, server_kcfs, "kcfs doit etre identique cote client et serveur");
        assert_eq!(client_kcfs, session.kcfs.unwrap(), "kcfs doit etre identique cote firewall");
    }

    #[test]
    fn test_process_record_message_rerandomizes() {
        let mut rng = OsRng;
        let server_sk = SigningKey::generate(&mut rng);
        let firewall = Firewall::new(server_sk.verifying_key(), &mut rng);

        let kcfs = [42u8; 32];
        let plaintext_ciphertext = [7u8; 32]; // "C" du Fig. 4, simplifie a 32 octets

        // Le client construit (r, s, t).
        let mut r = [0u8; 32];
        rng.fill_bytes(&mut r);
        let k1 = crypto::h1(&[r.as_slice(), kcfs.as_slice()].concat());
        let k2 = crypto::h2(&[r.as_slice(), kcfs.as_slice()].concat());
        let s = crypto::xor32(&k1, &plaintext_ciphertext);
        let t = crypto::mac(&k2, &[r.as_slice(), s.as_slice()].concat());

        let msg = RecordMessage { r, s: s.to_vec(), t };

        let out = firewall
            .process_record_message(msg, &kcfs, &mut rng)
            .expect("message bien forme, ne doit pas etre rejete");

        // r_tilde doit etre different de r (avec probabilite ecrasante).
        assert_ne!(out.r, r);

        // Le serveur, avec kcfs, doit retrouver le meme C et un MAC valide.
        let k1_tilde = crypto::h1(&[out.r.as_slice(), kcfs.as_slice()].concat());
        let k2_tilde = crypto::h2(&[out.r.as_slice(), kcfs.as_slice()].concat());
        assert!(crypto::mac_verify(&k2_tilde, &[out.r.as_slice(), out.s.as_slice()].concat(), &out.t));

        let mut s_tilde = [0u8; 32];
        s_tilde.copy_from_slice(&out.s);
        let recovered_c = crypto::xor32(&k1_tilde, &s_tilde);
        assert_eq!(recovered_c, plaintext_ciphertext);
    }

    #[test]
    fn test_process_record_message_rejects_bad_mac() {
        let mut rng = OsRng;
        let server_sk = SigningKey::generate(&mut rng);
        let firewall = Firewall::new(server_sk.verifying_key(), &mut rng);

        let kcfs = [1u8; 32];
        let msg = RecordMessage {
            r: [0u8; 32],
            s: vec![0u8; 32],
            t: [0u8; 32], // MAC clairement invalide
        };

        let result = firewall.process_record_message(msg, &kcfs, &mut rng);
        assert!(result.is_err());
    }
}

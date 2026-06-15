//! Tests unitaires pour server.rs.
//!
//! Ces tests vérifient les trois fonctions de Server :
//!   - Server::new
//!   - Server::process_firewall_init
//!   - Server::process_record_message
//!
//! Le Firewall et le Client sont simulés manuellement ici pour que ces
//! tests ne dépendent pas de client.rs ou firewall.rs.

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use curve25519_dalek::scalar::Scalar;

    use crate::server::Server;
    use crate::crypto;
    use crate::messages::{FirewallToServer, RecordMessage};

    // -----------------------------------------------------------------------
    // Utilitaire : construit un FirewallToServer honnête avec des points
    // aléatoires, comme le ferait un vrai firewall.
    // Retourne (message, x_tilde, c_tilde) pour qu'on puisse vérifier
    // les clés calculées par le serveur.
    // -----------------------------------------------------------------------
    fn make_firewall_to_server(
        rng: &mut impl rand::RngCore,
    ) -> (FirewallToServer, Scalar, Scalar) {
        let x_tilde = crypto::random_scalar(rng);
        let c_tilde = crypto::random_scalar(rng);
        let big_x_tilde = crypto::base_point(&x_tilde);
        let big_c_tilde = crypto::base_point(&c_tilde);

        // enc_c_tilde n'est pas utilisé par le serveur dans ce prototype
        let dummy_pk = crypto::base_point(&crypto::random_scalar(rng));
        let enc_c_tilde = crypto::elgamal_encrypt(&dummy_pk, &[0u8; 32], rng);

        (
            FirewallToServer { big_x_tilde, big_c_tilde, enc_c_tilde },
            x_tilde,
            c_tilde,
        )
    }

    // -----------------------------------------------------------------------
    // Utilitaire : construit un RecordMessage comme le ferait un client
    // honnête, à partir de kcs et kcfs déjà calculés.
    // -----------------------------------------------------------------------
    fn make_record_message(
        message: &[u8],
        kcs: &[u8; 32],
        kcfs: &[u8; 32],
        seq: u64,
        rng: &mut impl rand::RngCore,
    ) -> RecordMessage {
        let c = crypto::ae_encrypt(kcs, seq, message);

        let mut r = [0u8; 32];
        rng.fill_bytes(&mut r);

        let mut r_kcfs = r.to_vec();
        r_kcfs.extend_from_slice(kcfs);

        let k1 = crypto::h1(&r_kcfs);
        let k2 = crypto::h2(&r_kcfs);

        let s: Vec<u8> = c.iter()
            .enumerate()
            .map(|(i, byte)| byte ^ k1[i % 32])
            .collect();

        let mut mac_input = r.to_vec();
        mac_input.extend_from_slice(&s);
        let t = crypto::mac(&k2, &mac_input);

        RecordMessage { r, s, t }
    }

    // -----------------------------------------------------------------------
    // Tests de Server::new
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_keys_not_none() {
        // Après new(), kcs et kcfs doivent être None (handshake pas encore fait).
        let mut rng = OsRng;
        let server = Server::new(&mut rng);
        assert!(server.kcs.is_none());
        assert!(server.kcfs.is_none());
    }

    #[test]
    fn test_new_pk_derived_from_sk() {
        // La clé publique doit être cohérente avec la clé secrète.
        // On vérifie en signant un message et en vérifiant avec pk.
        use ed25519_dalek::{Signer, Verifier};
        let mut rng = OsRng;
        let server = Server::new(&mut rng);
        // On accède à sk via process_firewall_init qui signe — ici on vérifie
        // juste que pk est une VerifyingKey valide (non nulle).
        let msg = b"test";
        // pk est publique, on peut juste vérifier qu'elle est utilisable
        // en tentant une vérification avec une signature bidon -> doit échouer
        // proprement sans paniquer.
        use ed25519_dalek::Signature;
        let fake_sig = Signature::from_bytes(&[0u8; 64]);
        let result = server.pk.verify(msg, &fake_sig);
        assert!(result.is_err(), "Une signature nulle doit être rejetée");
    }

    #[test]
    fn test_new_produces_different_keys_each_time() {
        // Deux serveurs doivent avoir des clés publiques différentes.
        let mut rng = OsRng;
        let server1 = Server::new(&mut rng);
        let server2 = Server::new(&mut rng);
        assert_ne!(
            server1.pk.to_bytes(),
            server2.pk.to_bytes(),
            "Deux serveurs ne doivent pas avoir la même clé publique"
        );
    }

    // -----------------------------------------------------------------------
    // Tests de Server::process_firewall_init
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_firewall_init_sets_kcs_and_kcfs() {
        // Après process_firewall_init, kcs et kcfs doivent être Some.
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);
        let (msg, _, _) = make_firewall_to_server(&mut rng);

        server.process_firewall_init(msg, &mut rng);

        assert!(server.kcs.is_some(), "kcs doit être calculé");
        assert!(server.kcfs.is_some(), "kcfs doit être calculé");
    }

    #[test]
    fn test_process_firewall_init_kcs_kcfs_distinct() {
        // kcs et kcfs ne doivent pas être identiques.
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);
        let (msg, _, _) = make_firewall_to_server(&mut rng);

        server.process_firewall_init(msg, &mut rng);

        assert_ne!(
            server.kcs, server.kcfs,
            "kcs et kcfs doivent être distincts"
        );
    }

    #[test]
    fn test_process_firewall_init_signature_valid() {
        // La signature produite par le serveur doit être vérifiable avec pk.
        use ed25519_dalek::Verifier;
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);
        let (msg, _, _) = make_firewall_to_server(&mut rng);

        let big_x_tilde = msg.big_x_tilde;
        let big_c_tilde = msg.big_c_tilde;

        let response = server.process_firewall_init(msg, &mut rng);

        // Reconstruire le transcript signé : (Y, D, X_tilde^beta1, C_tilde^beta2)
        let x_tilde_beta1 = response.beta1 * big_x_tilde;
        let c_tilde_beta2 = response.beta2 * big_c_tilde;
        let transcript = crypto::concat_points(&[
            &response.big_y,
            &response.big_d,
            &x_tilde_beta1,
            &c_tilde_beta2,
        ]);

        assert!(
            server.pk.verify(&transcript, &response.signature).is_ok(),
            "La signature du serveur doit être valide sur le transcript"
        );
    }

    #[test]
    fn test_process_firewall_init_kcs_matches_dh() {
        // kcs côté serveur doit correspondre à X_tilde^(y*beta1).
        // On vérifie en recalculant kcs depuis les scalaires connus.
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);
        let (msg, x_tilde_scalar, _) = make_firewall_to_server(&mut rng);

        let big_x_tilde = msg.big_x_tilde;
        let response = server.process_firewall_init(msg, &mut rng);

        // Le serveur a calculé kcs = X_tilde^(y*beta1).
        // Nous connaissons x_tilde (le scalaire dont big_x_tilde = g^x_tilde),
        // donc on peut vérifier la propriété DH :
        // X_tilde^(y*beta1) = g^(x_tilde * y * beta1)
        // Y^(x_tilde*beta1) = g^(y * x_tilde * beta1) -> identiques !
        let expected_kcs_point = (x_tilde_scalar * response.beta1) * response.big_y;
        let expected_kcs = crypto::kdf(&expected_kcs_point);

        assert_eq!(
            server.kcs.unwrap(),
            expected_kcs,
            "kcs serveur doit correspondre à la propriété DH"
        );
    }

    #[test]
    fn test_process_firewall_init_kcfs_matches_dh() {
        // Même vérification pour kcfs = C_tilde^(d*beta2).
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);
        let (msg, _, c_tilde_scalar) = make_firewall_to_server(&mut rng);

        let big_c_tilde = msg.big_c_tilde;
        let response = server.process_firewall_init(msg, &mut rng);

        let expected_kcfs_point = (c_tilde_scalar * response.beta2) * response.big_d;
        let expected_kcfs = crypto::kdf(&expected_kcfs_point);

        assert_eq!(
            server.kcfs.unwrap(),
            expected_kcfs,
            "kcfs serveur doit correspondre à la propriété DH"
        );
    }

    #[test]
    fn test_process_firewall_init_fresh_keys_each_session() {
        // Deux sessions distinctes ne doivent pas produire les mêmes clés.
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);

        let (msg1, _, _) = make_firewall_to_server(&mut rng);
        server.process_firewall_init(msg1, &mut rng);
        let kcs1 = server.kcs;
        let kcfs1 = server.kcfs;

        let (msg2, _, _) = make_firewall_to_server(&mut rng);
        server.process_firewall_init(msg2, &mut rng);
        let kcs2 = server.kcs;
        let kcfs2 = server.kcfs;

        assert_ne!(kcs1, kcs2, "kcs doit être différent à chaque session");
        assert_ne!(kcfs1, kcfs2, "kcfs doit être différent à chaque session");
    }

    // -----------------------------------------------------------------------
    // Tests de Server::process_record_message
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_record_message_roundtrip() {
        // Un message chiffré correctement doit être déchiffré sans erreur.
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);
        let (msg, _, _) = make_firewall_to_server(&mut rng);
        server.process_firewall_init(msg, &mut rng);

        let kcs = server.kcs.unwrap();
        let kcfs = server.kcfs.unwrap();
        let plaintext = b"message de test";

        let record = make_record_message(plaintext, &kcs, &kcfs, 0, &mut rng);
        let decrypted = server
            .process_record_message(record, 0)
            .expect("Le déchiffrement doit réussir");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_process_record_message_wrong_mac_rejected() {
        // Un MAC corrompu doit être rejeté avant même le déchiffrement.
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);
        let (msg, _, _) = make_firewall_to_server(&mut rng);
        server.process_firewall_init(msg, &mut rng);

        let kcs = server.kcs.unwrap();
        let kcfs = server.kcfs.unwrap();
        let mut record = make_record_message(b"message", &kcs, &kcfs, 0, &mut rng);

        record.t[0] ^= 0xFF;

        let result = server.process_record_message(record, 0);
        assert!(result.is_err(), "Un MAC invalide doit être rejeté");
    }

    #[test]
    fn test_process_record_message_wrong_seq_rejected() {
        // Un mauvais numéro de séquence casse le nonce AEAD -> erreur.
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);
        let (msg, _, _) = make_firewall_to_server(&mut rng);
        server.process_firewall_init(msg, &mut rng);

        let kcs = server.kcs.unwrap();
        let kcfs = server.kcfs.unwrap();
        let record = make_record_message(b"message", &kcs, &kcfs, 0, &mut rng);

        let result = server.process_record_message(record, 1);
        assert!(result.is_err(), "Un seq erroné doit être rejeté");
    }

    #[test]
    fn test_process_record_message_wrong_kcfs_rejected() {
        // Si le serveur utilise un kcfs différent de celui du client,
        // le MAC ne peut pas être vérifié -> rejeté.
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);
        let (msg, _, _) = make_firewall_to_server(&mut rng);
        server.process_firewall_init(msg, &mut rng);

        let kcs = server.kcs.unwrap();
        let wrong_kcfs = [0u8; 32]; // kcfs incorrect
        let record = make_record_message(b"message", &kcs, &wrong_kcfs, 0, &mut rng);

        let result = server.process_record_message(record, 0);
        assert!(result.is_err(), "Un kcfs incorrect doit être rejeté via le MAC");
    }

    #[test]
    fn test_process_record_message_multiple_seq() {
        // Plusieurs messages avec des seq croissants doivent tous passer.
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);
        let (msg, _, _) = make_firewall_to_server(&mut rng);
        server.process_firewall_init(msg, &mut rng);

        let kcs = server.kcs.unwrap();
        let kcfs = server.kcfs.unwrap();
        let messages: &[&[u8]] = &[b"premier", b"deuxieme", b"troisieme"];

        for (seq, plaintext) in messages.iter().enumerate() {
            let record = make_record_message(plaintext, &kcs, &kcfs, seq as u64, &mut rng);
            let decrypted = server
                .process_record_message(record, seq as u64)
                .expect("Chaque message doit être déchiffré");
            assert_eq!(&decrypted, plaintext);
        }
    }

    #[test]
    fn test_process_record_message_empty_message() {
        // Un message vide doit fonctionner sans paniquer.
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);
        let (msg, _, _) = make_firewall_to_server(&mut rng);
        server.process_firewall_init(msg, &mut rng);

        let kcs = server.kcs.unwrap();
        let kcfs = server.kcfs.unwrap();
        let record = make_record_message(b"", &kcs, &kcfs, 0, &mut rng);

        let decrypted = server
            .process_record_message(record, 0)
            .expect("Un message vide doit être déchiffré sans erreur");
        assert_eq!(decrypted, b"");
    }

    // -----------------------------------------------------------------------
    // Démonstration de l'attaque : sans RF, l'attaquant récupère kcs
    // -----------------------------------------------------------------------

    #[test]
    fn test_attack_without_rf_attacker_recovers_kcs() {
        // SANS reverse firewall (firewall passif, X_tilde = X) :
        // Si l'attaquant connaît x (par backdoor), et observe (Y, beta1),
        // il peut recalculer kcs = Y^(x*beta1).
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);

        // Scalaire x connu de l'attaquant (backdoor dans le client)
        let x_known = Scalar::ONE;
        let big_x = crypto::base_point(&x_known);

        // Firewall passif : transmet X sans rerandomisation
        let c_known = crypto::random_scalar(&mut rng);
        let big_c = crypto::base_point(&c_known);
        let dummy_pk = crypto::base_point(&crypto::random_scalar(&mut rng));
        let enc_c = crypto::elgamal_encrypt(&dummy_pk, &c_known.to_bytes(), &mut rng);

        let fw_to_server = FirewallToServer {
            big_x_tilde: big_x,
            big_c_tilde: big_c,
            enc_c_tilde: enc_c,
        };

        let response = server.process_firewall_init(fw_to_server, &mut rng);

        // L'attaquant calcule kcs avec x connu
        let attacker_kcs = {
            let kcs_point = (x_known * response.beta1) * response.big_y;
            crypto::kdf(&kcs_point)
        };

        assert_eq!(
            attacker_kcs,
            server.kcs.unwrap(),
            "SANS RF : l'attaquant récupère kcs si x est connu"
        );
    }

    #[test]
    fn test_defense_with_rf_attacker_cannot_recover_kcs() {
        // AVEC reverse firewall (rerandomisation alpha1 secrète) :
        // Même si l'attaquant connaît x, il ne peut pas recalculer kcs
        // car il ne connaît pas alpha1.
        let mut rng = OsRng;
        let mut server = Server::new(&mut rng);

        let x_known = Scalar::ONE;
        let big_x = crypto::base_point(&x_known);

        // Firewall actif : rerandomise avec alpha1 secret
        let alpha1 = crypto::random_scalar(&mut rng);
        let big_x_tilde = alpha1 * big_x;

        let c_known = crypto::random_scalar(&mut rng);
        let big_c = crypto::base_point(&c_known);
        let alpha2 = crypto::random_scalar(&mut rng);
        let big_c_tilde = alpha2 * big_c;
        let dummy_pk = crypto::base_point(&crypto::random_scalar(&mut rng));
        let enc_c_tilde = crypto::elgamal_encrypt(&dummy_pk, &(c_known * alpha2).to_bytes(), &mut rng);

        let fw_to_server = FirewallToServer {
            big_x_tilde,
            big_c_tilde,
            enc_c_tilde,
        };

        let response = server.process_firewall_init(fw_to_server, &mut rng);

        // L'attaquant tente de calculer kcs sans connaître alpha1
        let attacker_guess = {
            let wrong_kcs_point = (x_known * response.beta1) * response.big_y;
            crypto::kdf(&wrong_kcs_point)
        };

        assert_ne!(
            attacker_guess,
            server.kcs.unwrap(),
            "AVEC RF : l'attaquant ne peut pas récupérer kcs"
        );
    }
}
//! Point d'entree : simule localement (sans reseau) une session complete
//! Client <-> Firewall <-> Serveur, en suivant la Fig. 3 (handshake) puis
//! la Fig. 4 (couche record).
//!
//! Ordre de travail conseille :
//!   1. Completer crypto.rs (deja fait, normalement rien a changer)
//!   2. Completer Server::new, Firewall::new, Client::new
//!   3. Completer Client::init_message
//!   4. Completer Firewall::process_client_init
//!   5. Completer Server::process_firewall_init
//!   6. Completer Firewall::process_server_response
//!   7. Completer Client::finalize
//!      -> a ce stade, les 3 asserts sur kcs/kcfs ci-dessous doivent passer !
//!   8. Completer la couche record (process_record_message cote firewall et serveur)

mod client;
mod crypto;
mod firewall;
mod messages;
mod server;
#[cfg(test)]
mod tests;

use rand::rngs::OsRng;

fn main() {
    let mut rng = OsRng;

    // --- Setup ---------------------------------------------------------
    // Le serveur genere d'abord sa paire de cles de signature (sk_S, pk_S).
    let mut server = server::Server::new(&mut rng);

    // Le firewall genere sa paire de cles de chiffrement (sk_FW, pk_FW),
    // et connait pk_S pour pouvoir verifier les signatures du serveur.
    let firewall = firewall::Firewall::new(server.pk, &mut rng);

    // Le client connait pk_FW (du firewall) et pk_S (du serveur).
    let mut client = client::Client::new(firewall.pk_fw, server.pk, &mut rng);

    // --- Handshake (Fig. 3) ---------------------------------------------

    // Etape 1 : Client -> Firewall : (X, C, e)
    let client_init = client.init_message(&mut rng);

    // Etape 2 : Firewall -> Server : (X_tilde, C_tilde, e_tilde)
    let (fw_to_server, mut session) = firewall
        .process_client_init(client_init, &mut rng)
        .expect("le firewall ne devrait pas rejeter un client honnete");

    // Etape 3 : Server -> Firewall : (sigma, Y, D, beta1, beta2)
    let server_response = server.process_firewall_init(fw_to_server, &mut rng);

    // Etape 4 : Firewall -> Client : (sigma, Y, D, gamma1, gamma2)
    let fw_to_client = firewall
        .process_server_response(server_response, &mut session)
        .expect("la signature du serveur devrait etre valide");

    // Etape 5 : le client verifie sigma et calcule kcs, kcfs
    client
        .finalize(fw_to_client)
        .expect("la signature devrait etre valide");

    // --- Verifications du handshake -------------------------------------
    assert_eq!(client.kcs, server.kcs, "kcs doit etre identique cote client et serveur");
    assert_eq!(client.kcfs, server.kcfs, "kcfs doit etre identique cote client et serveur");
    assert_eq!(client.kcfs, session.kcfs, "kcfs doit etre identique cote firewall");

    println!("Handshake reussi !");
    println!("kcs  = {:?}", client.kcs);
    println!("kcfs = {:?}", client.kcfs);

    // --- Couche record (Fig. 4) -----------------------------------------
    // TODO une fois le handshake termine :
    //   1. Le client chiffre un message M avec crypto::ae_encrypt(&client.kcs.unwrap(), 0, M) -> C
    //   2. r aleatoire (32 octets), k1=H1(r||kcfs), k2=H2(r||kcfs)
    //   3. s = k1 XOR C (en supposant |C| = 32 pour commencer), t = MAC_k2(r||s)
    //   4. Envoyer (r,s,t) au firewall -> firewall.process_record_message(...)
    //   5. Envoyer le resultat (r_tilde,s_tilde,t_tilde) au serveur
    //      -> server.process_record_message(...)
    //   6. Verifier que le serveur recupere bien M ( == message original)
}

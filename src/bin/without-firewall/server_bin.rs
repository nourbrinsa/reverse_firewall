//! Binaire Serveur (mode SANS firewall) : reçoit directement le Client.
//!
//! Démarrage :
//!   cargo run --bin server_direct

use rand::rngs::OsRng;
use std::net::TcpListener;
use std::path::PathBuf;
use reverse_firewall::{config, crypto, messages, net, server};

fn main() -> std::io::Result<()> {
    let cfg = config::ServerConfig::from_env();
    let pki_dir = PathBuf::from("pki");
    let mut rng = OsRng;

    println!("[Server] Chargement des clés PKI depuis {:?}...", pki_dir);
    let mut server = server::Server::from_pki(&pki_dir)
        .unwrap_or_else(|e| { eprintln!("[Server] Erreur PKI : {}", e); std::process::exit(1); });
    println!("[Server] Clés chargées — pk_server = {:?}", server.pk.to_bytes());

    let listener = TcpListener::bind(&cfg.listen_addr)?;
    println!("[Server] En écoute sur {}", cfg.listen_addr);

    let (mut stream, addr) = listener.accept()?;
    println!("[Server] Connexion depuis {}", addr);

    // Pas de ServerHello à envoyer : le Client a déjà pk_server via la PKI.

    // ── Handshake direct (Fig. 2) ────────────────────────────────────────────
    let init: messages::ClientInitDirect = net::recv_msg(&mut stream)?;
    println!("[Server] ClientInitDirect reçu");

    let response = server.process_client_direct(init, &mut rng);
    net::send_msg(&mut stream, &response)?;
    println!("[Server] ServerResponseDirect envoyé");

    // ── Boucle record layer (AEAD simple) ────────────────────────────────────
    let kcs = server.kcs.unwrap();
    loop {
        let record: messages::DirectRecord = match net::recv_msg(&mut stream) {
            Ok(r) => r,
            Err(e) => { println!("[Server] Client déconnecté : {}", e); break; }
        };

        match crypto::ae_decrypt(&kcs, record.seq, &record.ciphertext) {
            Ok(plaintext) => println!(
                "[Server] Message #{} : \"{}\"",
                record.seq,
                String::from_utf8_lossy(&plaintext)
            ),
            Err(e) => println!("[Server] Erreur déchiffrement #{} : {}", record.seq, e),
        }
    }

    println!("[Server] Session terminée");
    Ok(())
}
//! Binaire Serveur : charge ses clés depuis la PKI au lieu de les générer.
//!
//! Démarrage :
//!   PKI_DIR=./pki SERVER_ADDR=0.0.0.0:9090 cargo run --bin server
//!
//! Prérequis : avoir exécuté setup_pki.sh au préalable.

use rand::rngs::OsRng;
use std::net::TcpListener;
use std::path::PathBuf;
use reverse_firewall::{config, messages, net, server};

fn main() -> std::io::Result<()> {
    let cfg = config::ServerConfig::from_env();
    let pki_dir = PathBuf::from("pki");
    let mut rng = OsRng;

    // ── Chargement des clés depuis la PKI (vérifie le certificat CA) ──────
    println!("[Server] Chargement des clés PKI depuis {:?}...", pki_dir);
    let mut server = server::Server::from_pki(&pki_dir)
        .unwrap_or_else(|e| {
            eprintln!("[Server] Erreur PKI : {}", e);
            std::process::exit(1);
        });
    println!("[Server] Clés chargées — pk_server = {:?}", server.pk.to_bytes());

    // ── Écoute réseau ──────────────────────────────────────────────────────
    let listener = TcpListener::bind(&cfg.listen_addr)?;
    println!("[Server] En écoute sur {}", cfg.listen_addr);

    let (mut stream, addr) = listener.accept()?;
    println!("[Server] Connexion depuis {}", addr);

    // ── Étape 0 : Envoyer pk_server au Firewall ────────────────────────────
    // Le Firewall transmet ensuite pk_server au Client via FirewallHello.
    // Le Client vérifie l'authenticité de pk_server via le certificat CA.
    net::send_msg(&mut stream, &messages::ServerHello { pk_server: server.pk })?;
    println!("[Server] pk_server envoyée au Firewall");

    // ── Étape 3 : Réception de (X̃, C̃, ẽ) depuis le Firewall ───────────────
    let fw_to_server: messages::FirewallToServer = net::recv_msg(&mut stream)?;
    println!("[Server] FirewallToServer reçu");

    // ── Étape 4 : Calcul et envoi de la réponse signée ────────────────────
    let response = server.process_firewall_init(fw_to_server, &mut rng);
    net::send_msg(&mut stream, &response)?;
    println!("[Server] Réponse signée envoyée");
    println!("[Server] Handshake terminé");
    println!("[Server] kcs  = {:?}", server.kcs);
    println!("[Server] kcfs = {:?}", server.kcfs);

    // ── Boucle record layer ────────────────────────────────────────────────
    let mut seq = 0u64;
    loop {
        let record: messages::RecordMessage = match net::recv_msg(&mut stream) {
            Ok(r) => r,
            Err(e) => {
                println!("[Server] Firewall déconnecté : {}", e);
                break;
            }
        };

        match server.process_record_message(record, seq) {
            Ok(plaintext) => {
                println!(
                    "[Server] Message #{} : \"{}\"",
                    seq,
                    String::from_utf8_lossy(&plaintext)
                );
                seq += 1;
            }
            Err(e) => {
                println!("[Server] Erreur déchiffrement message #{} : {}", seq, e);
            }
        }
    }

    println!("[Server] Session terminée");
    Ok(())
}

//! Binaire Client (mode SANS firewall) : connexion directe au Serveur.
//!
//! Démarrage :
//!   cargo run --bin client_direct

use rand::rngs::OsRng;
use std::io::{self, BufRead};
use std::net::TcpStream;
use std::path::PathBuf;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use reverse_firewall::{client, config, crypto, messages, net, pki};

fn main() -> std::io::Result<()> {
    let cfg = config::ClientDirectConfig::from_env();
    let pki_dir = PathBuf::from("pki");
    let mut rng = OsRng;

    // ── Chargement du bundle de confiance (mode direct) ────────────────────
    // Ne vérifie que server.crt — pas de firewall.crt requis.
    println!("[Client] Vérification du certificat serveur dans {:?}...", pki_dir);
    let trust = pki::load_client_trust_bundle_direct(&pki_dir)
        .unwrap_or_else(|e| {
            eprintln!("[Client] Erreur PKI : {}", e);
            eprintln!("[Client] Assurez-vous que setup_pki.sh a été exécuté.");
            std::process::exit(1);
        });
    println!("[Client] PKI OK — pk_server vérifié par la CA");

    // ── Connexion directe au Serveur ────────────────────────────────────────
    println!("[Client] Connexion au Serveur sur {}...", cfg.server_addr);
    let mut stream = TcpStream::connect(&cfg.server_addr)?;
    println!("[Client] Connecté");

    // pk_fw n'existe pas en mode direct ; on passe un point factice,
    // jamais utilisé par init_message_direct / finalize_direct.
    let pk_fw_dummy = RISTRETTO_BASEPOINT_POINT;
    let mut client = client::Client::new(pk_fw_dummy, trust.pk_server, &mut rng);

    // ── Handshake direct (Fig. 2) ────────────────────────────────────────────
    let init = client.init_message_direct();
    net::send_msg(&mut stream, &init)?;
    println!("[Client] ClientInitDirect envoyé");

    let response: messages::ServerResponseDirect = net::recv_msg(&mut stream)?;
    println!("[Client] ServerResponseDirect reçu");

    client.finalize_direct(response)
        .unwrap_or_else(|e| { eprintln!("[Client] Handshake échoué : {}", e); std::process::exit(1); });

    println!("[Client] Handshake réussi !");
    println!("[Client] Tapez vos messages (Ctrl+C pour quitter) :");

    // ── Boucle record layer (AEAD simple, pas de couche kcfs) ──────────────
    let kcs = client.kcs.unwrap();
    let stdin = io::stdin();
    let mut seq = 0u64;

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() { continue; }

        let ciphertext = crypto::ae_encrypt(&kcs, seq, line.as_bytes());
        net::send_msg(&mut stream, &messages::DirectRecord { seq, ciphertext })?;
        println!("[Client] Message #{} envoyé", seq);
        seq += 1;
    }

    Ok(())
}
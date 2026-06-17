//! Binaire Firewall : charge ses clés depuis la PKI au lieu de les générer.
//!
//! Démarrage :
//!   cargo run --bin firewall

use rand::rngs::OsRng;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use reverse_firewall::{config, firewall, messages, net};

fn main() -> std::io::Result<()> {
    let cfg = config::FirewallConfig::from_env();
    let pki_dir = PathBuf::from("pki");
    let mut rng = OsRng;

    // ── Chargement des clés PKI (firewall + pk_server) ─────────────────────
    // from_pki() charge sk_fw/pk_fw ET pk_server, tous deux vérifiés
    // localement contre ca.crt. Publie aussi pk_fw pour le client.
    println!("[Firewall] Chargement des clés PKI depuis {:?}...", pki_dir);
    let fw = firewall::Firewall::from_pki(&pki_dir)
        .unwrap_or_else(|e| { eprintln!("[Firewall] Erreur PKI : {}", e); std::process::exit(1); });
    println!("[Firewall] Clés chargées et pk_fw publiée");

    // ── Connexion au Serveur ─────────────────────────────────────
    println!("[Firewall] Connexion au serveur sur {}...", cfg.server_addr);
    let mut server_stream = TcpStream::connect(&cfg.server_addr)?;
    println!("[Firewall] Connecté au serveur");

    // ── Écoute du Client ─────────────────────────────────────────
    let listener = TcpListener::bind(&cfg.listen_addr)?;
    println!("[Firewall] En écoute sur {} pour le Client", cfg.listen_addr);

    let (mut client_stream, addr) = listener.accept()?;
    println!("[Firewall] Connexion depuis {}", addr);

    // ── Handshake ─────────────────────────────────────────────────────────
    let client_init: messages::ClientInit = net::recv_msg(&mut client_stream)?;
    println!("[Firewall] ClientInit reçu");

    let (fw_to_server, mut session) = fw
        .process_client_init(client_init, &mut rng)
        .unwrap_or_else(|e| { eprintln!("[Firewall] Client invalide : {}", e); std::process::exit(1); });

    net::send_msg(&mut server_stream, &fw_to_server)?;
    println!("[Firewall] FirewallToServer envoyé");

    let server_response: messages::ServerResponse = net::recv_msg(&mut server_stream)?;
    println!("[Firewall] ServerResponse reçu");

    let fw_to_client = fw
        .process_server_response(server_response, &mut session)
        .unwrap_or_else(|e| { eprintln!("[Firewall] Signature invalide : {}", e); std::process::exit(1); });

    net::send_msg(&mut client_stream, &fw_to_client)?;
    println!("[Firewall] FirewallToClient envoyé — handshake terminé");
    println!("[Firewall] kcfs = {:?}", session.kcfs);

    // ── Boucle record layer ────────────────────────────────────────────────
    let kcfs = session.kcfs.expect("kcfs manquant après handshake");
    loop {
        let client_record: messages::RecordMessage = match net::recv_msg(&mut client_stream) {
            Ok(r) => { 
                println!("[Firewall] Message envoyé au serveur");
                r
            },
            Err(e) => { println!("[Firewall] Client déconnecté : {}", e); break; }
        };

        let fw_record: messages::RecordMessage = match fw.process_record_message(client_record, &kcfs, &mut rng) {
            Ok(r) => r,
            Err(e) => { println!("[Firewall] Message rejeté : {}", e); continue; }
        };

        if let Err(e) = net::send_msg(&mut server_stream, &fw_record) {
            println!("[Firewall] Serveur déconnecté : {}", e);
            break;
        }
    }

    println!("[Firewall] Session terminée");
    Ok(())
}

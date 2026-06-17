//! Binaire Firewall : charge ses clés depuis la PKI au lieu de les générer.
//!
//! Démarrage :
//!   PKI_DIR=./pki FIREWALL_LISTEN=0.0.0.0:8080 FIREWALL_SERVER_ADDR=127.0.0.1:9090 \
//!   cargo run --bin firewall
//!
//! Prérequis : setup_pki.sh exécuté, server déjà démarré.

use rand::rngs::OsRng;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use reverse_firewall::{config, firewall, messages, net};

fn main() -> std::io::Result<()> {
    let cfg = config::FirewallConfig::from_env();
    let pki_dir = PathBuf::from("pki");
    let mut rng = OsRng;

    // ── Étape 1 : Connexion au Serveur ─────────────────────────────────────
    println!("[Firewall] Connexion au serveur sur {}...", cfg.server_addr);
    let mut server_stream = TcpStream::connect(&cfg.server_addr)?;
    println!("[Firewall] Connecté au serveur");

    // ── Étape 2 : Réception de pk_server via ServerHello ──────────────────
    let server_hello: messages::ServerHello = net::recv_msg(&mut server_stream)?;
    let pk_server = server_hello.pk_server;
    println!("[Firewall] pk_server reçue : {:?}", pk_server.to_bytes());

    // ── Chargement des clés PKI + publication de pk_fw ────────────────────
    // from_pki() :
    //   1. Vérifie firewall.crt auprès de ca.crt (openssl verify)
    //   2. Extrait sk_fw depuis firewall.key (seed Ed25519 → Scalar Ristretto)
    //   3. Calcule pk_fw = sk_fw · G
    //   4. Publie pk_fw dans pki/firewall_pk_ristretto.bin
    //      (fichier que le Client lira après avoir vérifié le certificat)
    println!("[Firewall] Chargement des clés PKI depuis {:?}...", pki_dir);
    let fw = firewall::Firewall::from_pki(&pki_dir, pk_server)
        .unwrap_or_else(|e| {
            eprintln!("[Firewall] Erreur PKI : {}", e);
            std::process::exit(1);
        });
    println!("[Firewall] Clés chargées et pk_fw publiée");

    // ── Étape 3 : Écoute du Client ─────────────────────────────────────────
    let listener = TcpListener::bind(&cfg.listen_addr)?;
    println!("[Firewall] En écoute sur {} pour le Client", cfg.listen_addr);

    let (mut client_stream, addr) = listener.accept()?;
    println!("[Firewall] Connexion depuis {}", addr);

    // ── Étape 4 : Envoi de FirewallHello au Client ─────────────────────────
    // Le Client utilisera pk_fw et pk_server pour initialiser son état.
    // La confiance dans pk_server et pk_fw vient de la PKI :
    //   - pk_server : le Client vérifie server.crt via ca.crt
    //   - pk_fw     : le Client lit firewall_pk_ristretto.bin après avoir
    //                 vérifié firewall.crt via ca.crt
    net::send_msg(&mut client_stream, &messages::FirewallHello {
        pk_fw: fw.pk_fw,
        pk_server,
    })?;
    println!("[Firewall] FirewallHello envoyé au Client");

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

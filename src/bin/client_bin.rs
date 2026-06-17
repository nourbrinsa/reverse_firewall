//! Binaire Client : vérifie les clés publiques via la PKI avant de les utiliser.
//!
//! Démarrage :
//!   PKI_DIR=./pki CLIENT_ADDR=127.0.0.1:8080 cargo run --bin client
//!
//! Prérequis : le script de déploiement PKI a déjà distribué le bundle client.

use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{self, BufRead};
use std::net::TcpStream;
use std::path::PathBuf;
use reverse_firewall::{client, config, crypto, messages, net, pki};

fn main() -> std::io::Result<()> {
    let cfg = config::ClientConfig::from_env();
    let pki_dir = PathBuf::from(std::env::var("PKI_DIR").unwrap_or_else(|_| "pki".to_string()));
    let mut rng = OsRng;

    // ── Chargement du bundle de confiance depuis la PKI ────────────────────
    // load_client_trust_bundle() :
    //   1. Vérifie server.crt et firewall.crt auprès de ca.crt
    //   2. Extrait pk_server depuis server.crt
    //   3. Lit pk_fw depuis firewall_pk_ristretto.bin
    //      (généré pendant le provisioning PKI puis distribué au Client)
    println!("[Client] Vérification des certificats PKI dans {:?}...", pki_dir);
    let trust = pki::load_client_trust_bundle(&pki_dir)
        .unwrap_or_else(|e| {
            eprintln!("[Client] Erreur PKI : {}", e);
            eprintln!("[Client] Assurez-vous que :");
            eprintln!("  1. Le script de déploiement PKI a été exécuté depuis RF");
            eprintln!("  2. ca.crt, server.crt, firewall.crt, server_pub.pem et firewall_pk_ristretto.bin existent dans PKI_DIR");
            std::process::exit(1);
        });
    println!("[Client] PKI OK — pk_server et pk_fw vérifiés par la CA");

    // ── Connexion au Firewall ──────────────────────────────────────────────
    println!("[Client] Connexion au Firewall sur {}...", cfg.firewall_addr);
    let mut stream = TcpStream::connect(&cfg.firewall_addr)?;
    println!("[Client] Connecté");

    // ── Réception de FirewallHello ─────────────────────────────────────────
    // Le Firewall nous envoie (pk_fw, pk_server) en clair.
    // On vérifie que ces valeurs correspondent à ce que la PKI nous a fourni.
    // Si elles diffèrent, un imposteur se fait passer pour le Firewall.
    let hello: messages::FirewallHello = net::recv_msg(&mut stream)?;

    // ── Vérification PKI des clés reçues ──────────────────────────────────
    if hello.pk_server != trust.pk_server {
        eprintln!("[Client] ALERTE : pk_server reçue ne correspond pas au certificat PKI !");
        eprintln!("  Reçue   : {:?}", hello.pk_server.to_bytes());
        eprintln!("  Attendue: {:?}", trust.pk_server.to_bytes());
        std::process::exit(1);
    }
    if hello.pk_fw.compress().to_bytes() != trust.pk_fw.compress().to_bytes() {
        eprintln!("[Client] ALERTE : pk_fw reçue ne correspond pas au certificat PKI !");
        std::process::exit(1);
    }
    println!("[Client] pk_server et pk_fw vérifiées — identiques à la PKI ✓");

    // ── Initialisation du Client avec les clés certifiées ─────────────────
    // On utilise trust.pk_fw et trust.pk_server (issus de la PKI)
    // plutôt que hello.pk_fw et hello.pk_server (reçus du réseau),
    // même si on vient de vérifier qu'ils sont identiques.
    // C'est la bonne pratique : ne jamais utiliser directement ce qui vient
    // du réseau, mais toujours la version certifiée.
    let mut client = client::Client::new(trust.pk_fw, trust.pk_server, &mut rng);

    // ── Handshake ─────────────────────────────────────────────────────────
    let client_init = client.init_message(&mut rng);
    net::send_msg(&mut stream, &client_init)?;
    println!("[Client] ClientInit envoyé");

    let fw_to_client: messages::FirewallToClient = net::recv_msg(&mut stream)?;
    println!("[Client] FirewallToClient reçu");

    client.finalize(fw_to_client)
        .unwrap_or_else(|e| { eprintln!("[Client] Handshake échoué : {}", e); std::process::exit(1); });

    println!("[Client] Handshake réussi !");
    println!("[Client] Tapez vos messages (Ctrl+C pour quitter) :");

    // ── Boucle record layer ────────────────────────────────────────────────
    let kcs  = client.kcs.unwrap();
    let kcfs = client.kcfs.unwrap();
    let stdin = io::stdin();
    let mut seq = 0u64;

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() { continue; }

        let big_c = crypto::ae_encrypt(&kcs, seq, line.as_bytes());

        let mut r = [0u8; 32];
        rng.fill_bytes(&mut r);

        let r_kcfs: Vec<u8> = r.iter().chain(kcfs.iter()).copied().collect();
        let k1 = crypto::h1(&r_kcfs);
        let k2 = crypto::h2(&r_kcfs);

        let s: Vec<u8> = big_c.iter()
            .enumerate()
            .map(|(i, &b)| b ^ k1[i % 32])
            .collect();
        let t = crypto::mac(&k2, &[r.as_slice(), s.as_slice()].concat());

        net::send_msg(&mut stream, &messages::RecordMessage { r, s, t })?;
        println!("[Client] Message #{} envoyé", seq);
        seq += 1;
    }

    Ok(())
}

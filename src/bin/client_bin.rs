//! Binaire Client : vérifie les clés publiques via la PKI avant de les utiliser.
//!
//! Démarrage :
//! cargo run --bin client
//! Prérequis : setup_pki.sh exécuté, server et firewall déjà démarrés.

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
    //      (publié par le Firewall après vérification de son propre certificat)
    println!("[Client] Vérification des certificats PKI dans {:?}...", pki_dir);
    let trust = pki::load_client_trust_bundle(&pki_dir)
        .unwrap_or_else(|e| {
            eprintln!("[Client] Erreur PKI : {}", e);
            eprintln!("[Client] Assurez-vous que :");
            eprintln!("  1. setup_pki.sh a été exécuté");
            eprintln!("  2. Le Firewall a démarré (pour générer firewall_pk_ristretto.bin)");
            std::process::exit(1);
        });
    println!("[Client] PKI OK — pk_server et pk_fw vérifiés par la CA");

    // ── Connexion au Firewall ──────────────────────────────────────────────
    println!("[Client] Connexion au Firewall sur {}...", cfg.firewall_addr);
    let mut stream = TcpStream::connect(&cfg.firewall_addr)?;
    println!("[Client] Connecté");

    // pk_fw et pk_server viennent déjà de la PKI.
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

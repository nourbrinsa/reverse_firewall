//! Outil de provisioning PKI.
//!
//! Génère `firewall_pk_ristretto.bin` à partir de `firewall.key` pendant le
//! déploiement, avant le démarrage du Firewall et du Client.
//!
//! Usage :
//!   cargo run --bin pki_export_firewall_pk -- <firewall.key> <firewall_pk_ristretto.bin>

use std::env;
use std::path::PathBuf;
use reverse_firewall::pki;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "Usage: {} <firewall.key> <firewall_pk_ristretto.bin>",
            args.get(0).map(String::as_str).unwrap_or("pki_export_firewall_pk")
        );
        std::process::exit(2);
    }

    let firewall_key = PathBuf::from(&args[1]);
    let output = PathBuf::from(&args[2]);

    if let Err(e) = pki::export_firewall_pk_from_private_key(&firewall_key, &output) {
        eprintln!("[PKI] Erreur export pk_fw : {}", e);
        std::process::exit(1);
    }
}

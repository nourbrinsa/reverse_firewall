mod client;
mod crypto;
mod firewall;
mod messages;
mod server;
mod pki;
mod net;
mod config;

use messages::RecordMessage;
use rand::rngs::OsRng;

fn main() {
    let mut rng = OsRng;

    // --- Setup ---------------------------------------------------------
    let mut server = server::Server::new(&mut rng);
    let firewall = firewall::Firewall::new(server.pk, &mut rng);
    let mut client = client::Client::new(firewall.pk_fw, server.pk, &mut rng);

    // --- Handshake (Fig. 3) --------------------------------------------

    // Etape 1 : Client -> Firewall : (X, C, e)
    let client_init = client.init_message(&mut rng);

    // Etape 2 : Firewall -> Server : (X~, C~, e~)
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

    // --- Verifications du handshake ------------------------------------
    assert_eq!(client.kcs, server.kcs,     "kcs doit etre identique cote client et serveur");
    assert_eq!(client.kcfs, server.kcfs,   "kcfs doit etre identique cote client et serveur");
    assert_eq!(client.kcfs, session.kcfs,  "kcfs doit etre identique cote firewall");

    println!("Handshake reussi !");
    println!("kcs  = {:?}", client.kcs);
    println!("kcfs = {:?}", client.kcfs);

    // --- Couche record (Fig. 4) ----------------------------------------
    let message = b"Hello from client!";
    println!("\nMessage original : \"{}\"", std::str::from_utf8(message).unwrap());

    let kcs  = client.kcs.unwrap();
    let kcfs = client.kcfs.unwrap();
    let seq  = 0u64;

    // Etape 1 (client) : chiffrer M avec kcs -> C (AEAD)
    let big_c = crypto::ae_encrypt(&kcs, seq, message);

    // Etape 2 (client) : choisir r, deriver k1 = H1(r||kcfs), k2 = H2(r||kcfs)
    let mut r = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut r);

    let r_kcfs = [r.as_slice(), kcfs.as_slice()].concat();
    let k1 = crypto::h1(&r_kcfs);
    let k2 = crypto::h2(&r_kcfs);

    // Etape 3 (client) : s = k1 XOR C, t = MAC_k2(r || s)
    // C peut faire plus de 32 octets (AEAD ajoute 16 octets de tag).
    // On XOR octet par octet en cyclant sur k1 (32 octets).
    let s: Vec<u8> = big_c
    .iter()
    .enumerate()
    .map(|(i, &byte)| byte ^ k1[i % 32])
    .collect();

    let t = crypto::mac(&k2, &[r.as_slice(), s.as_slice()].concat());

    let client_record = RecordMessage { r, s: s.to_vec(), t };
    println!("Client envoie (r, s, t) au firewall.");

    // Etape 4 (firewall) : rerandomiser (r, s, t) -> (r~, s~, t~)
    let fw_record = firewall
        .process_record_message(client_record, &kcfs, &mut rng)
        .expect("le firewall ne devrait pas rejeter un message honnete");
    println!("Firewall renvoie (r~, s~, t~) au serveur.");

    // Etape 5 (serveur) : verifier le MAC, retrouver C, dechiffrer avec kcs -> M
    let recovered = server
        .process_record_message(fw_record, seq)
        .expect("le serveur doit pouvoir dechiffrer le message");

    println!("Serveur recupere : \"{}\"", std::str::from_utf8(&recovered).unwrap());

    // --- Verification finale -------------------------------------------
    assert_eq!(
        recovered, message,
        "le message recupere doit etre identique au message original"
    );
    println!("\nCouche record reussie !");
}
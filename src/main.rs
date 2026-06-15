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
    assert_eq!(client.kcs, server.kcs, "kcs doit etre identique cote client et serveur");
    assert_eq!(client.kcfs, server.kcfs, "kcfs doit etre identique cote client et serveur");
    assert_eq!(client.kcfs, session.kcfs, "kcfs doit etre identique cote firewall");

    println!("Handshake reussi !");
    println!("kcs  = {:?}", client.kcs);
    println!("kcfs = {:?}", client.kcfs);

    // --- Couche record (Fig. 4) ----------------------------------------
    // Le message que le client veut envoyer au serveur.
    let message = b"Hello from client!";
    println!("\nMessage original : {:?}", std::str::from_utf8(message).unwrap());

    let kcs  = client.kcs.unwrap();
    let kcfs = client.kcfs.unwrap();

    // Etape 1 (client) : chiffrer M avec kcs -> C (AEAD, seq=0)
    // C est le chiffre interne, protege par kcs (inconnu du firewall).
    let seq = 0u64;
    let big_c = crypto::ae_encrypt(&kcs, seq, message);

    // Etape 2 (client) : choisir r aleatoire, deriver k1 et k2 depuis (r || kcfs)
    // k1 sert de masque one-time-pad sur C.
    // k2 sert de cle MAC pour authentifier (r, s).
    let mut r = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut r);

    let mut r_kcfs = [0u8; 64];
    r_kcfs[..32].copy_from_slice(&r);
    r_kcfs[32..].copy_from_slice(&kcfs);

    let k1 = crypto::h1(&r_kcfs);
    let k2 = crypto::h2(&r_kcfs);

    // Etape 3 (client) : s = k1 XOR C, t = MAC_k2(r || s)
    // On tronque / padde C a 32 octets pour le XOR (cf prototype).
    let mut big_c_32 = [0u8; 32];
    let len = big_c.len().min(32);
    big_c_32[..len].copy_from_slice(&big_c[..len]);

    let s = crypto::xor32(&k1, &big_c_32);

    let mut r_s = [0u8; 64];
    r_s[..32].copy_from_slice(&r);
    r_s[32..].copy_from_slice(&s);
    let t = crypto::mac(&k2, &r_s);

    println!("Client envoie (r, s, t) au firewall.");

    // Etape 4 (firewall) : rerandomiser (r, s, t) -> (r~, s~, t~)
    // Le firewall dechiffre la couche kcfs, puis rechiffre avec un r~ frais.
    let mut r_tilde = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut r_tilde);

    // Le firewall recalcule k1 depuis (r || kcfs) pour retrouver C~ = k1 XOR s
    let fw_kcfs = session.kcfs.unwrap();

    let mut r_kcfs_fw = [0u8; 64];
    r_kcfs_fw[..32].copy_from_slice(&r);
    r_kcfs_fw[32..].copy_from_slice(&fw_kcfs);

    let fw_k1 = crypto::h1(&r_kcfs_fw);
    let fw_k2 = crypto::h2(&r_kcfs_fw);

    // Verifier le MAC avant de continuer (le firewall rejette si invalide)
    assert!(
        crypto::mac_verify(&fw_k2, &r_s, &t),
        "le firewall rejette : MAC invalide"
    );

    // C~ = k1 XOR s  (retrouve le chiffre interne)
    let c_tilde_32 = crypto::xor32(&fw_k1, &s);

    // Rechiffrer avec r~ frais
    let mut r_tilde_kcfs = [0u8; 64];
    r_tilde_kcfs[..32].copy_from_slice(&r_tilde);
    r_tilde_kcfs[32..].copy_from_slice(&fw_kcfs);

    let fw_k1_tilde = crypto::h1(&r_tilde_kcfs);
    let fw_k2_tilde = crypto::h2(&r_tilde_kcfs);

    let s_tilde = crypto::xor32(&fw_k1_tilde, &c_tilde_32);

    let mut r_tilde_s_tilde = [0u8; 64];
    r_tilde_s_tilde[..32].copy_from_slice(&r_tilde);
    r_tilde_s_tilde[32..].copy_from_slice(&s_tilde);
    let t_tilde = crypto::mac(&fw_k2_tilde, &r_tilde_s_tilde);

    println!("Firewall renvoie (r~, s~, t~) au serveur.");

    // Etape 5 (serveur) : dechiffrer (r~, s~, t~) -> M
    let srv_kcs  = server.kcs.unwrap();
    let srv_kcfs = server.kcfs.unwrap();

    // Verifier le MAC
    let mut r_tilde_kcfs_srv = [0u8; 64];
    r_tilde_kcfs_srv[..32].copy_from_slice(&r_tilde);
    r_tilde_kcfs_srv[32..].copy_from_slice(&srv_kcfs);

    let srv_k1_tilde = crypto::h1(&r_tilde_kcfs_srv);
    let srv_k2_tilde = crypto::h2(&r_tilde_kcfs_srv);

    assert!(
        crypto::mac_verify(&srv_k2_tilde, &r_tilde_s_tilde, &t_tilde),
        "le serveur rejette : MAC invalide"
    );

    // Retrouver C~~ = k1~ XOR s~  (= le chiffre interne C)
    let c_tilde_tilde = crypto::xor32(&srv_k1_tilde, &s_tilde);

    // Dechiffrer avec kcs pour retrouver M
    let mut c_final = big_c.clone();
    c_final[..len].copy_from_slice(&c_tilde_tilde[..len]);

    let recovered = crypto::ae_decrypt(&srv_kcs, seq, &c_final)
        .expect("le serveur doit pouvoir dechiffrer le message");

    println!("Serveur recupere : {:?}", std::str::from_utf8(&recovered).unwrap());

    // --- Verification finale -------------------------------------------
    assert_eq!(
        recovered, message,
        "le message recupere doit etre identique au message original"
    );

    println!("\nCouche record reussie ! Le message a ete transmis integre.");
}
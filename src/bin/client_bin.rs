use std::net::TcpStream;
use rand::rngs::OsRng;
use rand::RngCore;

use reverse_firewall::{client, crypto, messages, net, config};

fn main() -> std::io::Result<()> {
    let cfg = config::ClientConfig::from_env();
    let mut rng = OsRng;

    println!("[Client] connexion au firewall sur {}...", cfg.firewall_addr);
    let mut stream = TcpStream::connect(&cfg.firewall_addr)?;
    println!("[Client] connecte");

    // Etape 0 : recevoir pk_fw + pk_server
    let hello: messages::FirewallHello = net::recv_msg(&mut stream)?;
    println!("[Client] hello recu (pk_fw, pk_server)");

    let mut client = client::Client::new(hello.pk_fw, hello.pk_server, &mut rng);

    // Etape 1 : envoyer (X, C, e)
    let client_init = client.init_message(&mut rng);
    net::send_msg(&mut stream, &client_init)?;
    println!("[Client] ClientInit envoye");

    // Etape 7 (recue) : (sigma, Y, D, gamma1, gamma2)
    let fw_to_client: messages::FirewallToClient = net::recv_msg(&mut stream)?;
    println!("[Client] FirewallToClient recu");

    client.finalize(fw_to_client).expect("signature invalide");

    println!("[Client] Handshake reussi !");
    println!("[Client] kcs  = {:?}", client.kcs);
    println!("[Client] kcfs = {:?}", client.kcfs);

    // --- Couche record ---
    let message = b"Hello from client!";
    println!("\n[Client] message original : \"{}\"", std::str::from_utf8(message).unwrap());

    let kcs = client.kcs.unwrap();
    let kcfs = client.kcfs.unwrap();
    let seq = 0u64;

    let big_c = crypto::ae_encrypt(&kcs, seq, message);

    let mut r = [0u8; 32];
    rng.fill_bytes(&mut r);

    let r_kcfs = [r.as_slice(), kcfs.as_slice()].concat();
    let k1 = crypto::h1(&r_kcfs);
    let k2 = crypto::h2(&r_kcfs);

    let s: Vec<u8> = big_c
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ k1[i % 32])
        .collect();

    let t = crypto::mac(&k2, &[r.as_slice(), s.as_slice()].concat());

    let record = messages::RecordMessage { r, s, t };
    net::send_msg(&mut stream, &record)?;
    println!("[Client] message record envoye");

    Ok(())
}
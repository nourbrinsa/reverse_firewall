use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{self, BufRead};
use std::net::TcpStream;
use reverse_firewall::{client, config, crypto, messages, net};

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
    println!("[Client] Tapez vos messages (Ctrl+C pour quitter) :");

    let kcs = client.kcs.unwrap();
    let kcfs = client.kcfs.unwrap();
    let stdin = io::stdin();
    let mut seq = 0u64;

    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }

        // encrypt with kcs
        let big_c = crypto::ae_encrypt(&kcs, seq, line.as_bytes());

        // build (r, s, t)
        let mut r = [0u8; 32];
        rng.fill_bytes(&mut r);
        let r_kcfs = [r.as_slice(), kcfs.as_slice()].concat();
        let k1 = crypto::h1(&r_kcfs);
        let k2 = crypto::h2(&r_kcfs);
        let s: Vec<u8> = big_c
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ k1[i % 32])
            .collect();
        let t = crypto::mac(&k2, &[r.as_slice(), s.as_slice()].concat());

        net::send_msg(&mut stream, &messages::RecordMessage { r, s, t })?;
        println!("[Client] message #{} envoye", seq);

        seq += 1;
    }

    Ok(())
}
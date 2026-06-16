use std::net::TcpListener;
use rand::rngs::OsRng;


use reverse_firewall::{server, messages, net,config};

fn main() -> std::io::Result<()> {
    let cfg = config::ServerConfig::from_env();
    let mut rng = OsRng;
    let mut server = server::Server::new(&mut rng);

    let listener = TcpListener::bind(&cfg.listen_addr)?;
    println!("[Server] en ecoute sur {}", cfg.listen_addr);

    let (mut stream, addr) = listener.accept()?;
    println!("[Server] connexion depuis {}", addr);

    // Etape 0 : envoyer pk_server au firewall
    net::send_msg(&mut stream, &messages::ServerHello { pk_server: server.pk })?;
    println!("[Server] pk envoyee au firewall");

    // Etape 3 : reception de (X~, C~, e~) depuis le firewall
    let fw_to_server: messages::FirewallToServer = net::recv_msg(&mut stream)?;
    println!("[Server] recu FirewallToServer");

    let response = server.process_firewall_init(fw_to_server, &mut rng);

    // Etape 4 : Envoi de (sigma, Y, D, beta1, beta2)
    net::send_msg(&mut stream, &response)?;
    println!("[Server] reponse signee envoyee");

    println!("[Server] kcs  = {:?}", server.kcs);
    println!("[Server] kcfs = {:?}", server.kcfs);

    // --- Couche record ---
    println!("[Server] en attente du message record...");
    let record: messages::RecordMessage = net::recv_msg(&mut stream)?;

    let seq = 0u64;
    let plaintext = server
        .process_record_message(record, seq)
        .expect("dechiffrement echoue");

    println!("[Server] message recu et dechiffre : \"{}\"",
        String::from_utf8_lossy(&plaintext));

    Ok(())
}
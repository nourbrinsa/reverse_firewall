use rand::rngs::OsRng;
use std::net::TcpListener;
use reverse_firewall::{config, messages, net, server};

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

    println!("[Server] handshake termine, en attente des messages...");
    println!("[Server] kcs  = {:?}", server.kcs);
    println!("[Server] kcfs = {:?}", server.kcfs);

    // record loop
    let mut seq = 0u64;
    loop {
        let record: messages::RecordMessage = match net::recv_msg(&mut stream) {
            Ok(r) => r,
            Err(e) => {
                println!("[Server] firewall deconnecte : {}", e);
                break;
            }
        };

        match server.process_record_message(record, seq) {
            Ok(plaintext) => {
                println!(
                    "[Server] message #{} : \"{}\"",
                    seq,
                    String::from_utf8_lossy(&plaintext)
                );
                seq += 1;
            }
            Err(e) => {
                println!("[Server] erreur dechiffrement message #{} : {}", seq, e);
                // do NOT increment seq on error — the counters must stay in sync
            }
        }
    }

    println!("[Server] session terminee");
    Ok(())
}
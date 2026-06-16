use std::net::{TcpListener, TcpStream};
use rand::rngs::OsRng;

use reverse_firewall::{firewall, messages, net, config};

fn main() -> std::io::Result<()> {
    let cfg = config::FirewallConfig::from_env();
    let mut rng = OsRng;

    // 1. Se connecter au serveur
    println!("[Firewall] connexion au serveur sur {}...", cfg.server_addr);
    let mut server_stream = TcpStream::connect(&cfg.server_addr)?;
    println!("[Firewall] connecte au serveur");

    let server_hello: messages::ServerHello = net::recv_msg(&mut server_stream)?;
    let pk_server = server_hello.pk_server;
    println!("[Firewall] pk_server recue");

    // 2. Setup du firewall
    let fw = firewall::Firewall::new(pk_server, &mut rng);

    // 3. Ecouter le client
    let listener = TcpListener::bind(&cfg.listen_addr)?;
    println!("[Firewall] en ecoute sur {} pour le client", cfg.listen_addr);

    let (mut client_stream, addr) = listener.accept()?;
    println!("[Firewall] connexion depuis {}", addr);

    // 4. Envoyer pk_fw + pk_server au client
    net::send_msg(&mut client_stream, &messages::FirewallHello {
        pk_fw: fw.pk_fw,
        pk_server,
    })?;
    println!("[Firewall] hello envoye au client");

    // --- Handshake ---

    // Etape 1 : reception de (X, C, e) depuis le client
    let client_init: messages::ClientInit = net::recv_msg(&mut client_stream)?;
    println!("[Firewall] recu ClientInit");

    let (fw_to_server, mut session) = fw
        .process_client_init(client_init, &mut rng)
        .expect("client invalide");

    // Etape 2 : envoi de (X~, C~, e~) au serveur
    net::send_msg(&mut server_stream, &fw_to_server)?;
    println!("[Firewall] envoye FirewallToServer");

    // Etape 3 : reception de (sigma, Y, D, beta1, beta2) depuis le serveur
    let server_response: messages::ServerResponse = net::recv_msg(&mut server_stream)?;
    println!("[Firewall] recu ServerResponse");

    let fw_to_client = fw
        .process_server_response(server_response, &mut session)
        .expect("signature invalide");

    println!("[Firewall] kcfs = {:?}", session.kcfs);

    // Etape 4 : envoi de (sigma, Y, D, gamma1, gamma2) au client
    net::send_msg(&mut client_stream, &fw_to_client)?;
    println!("[Firewall] envoye FirewallToClient");

    // --- Couche record : pont transparent ---
    println!("[Firewall] en attente du message record du client...");
    let client_record: messages::RecordMessage = net::recv_msg(&mut client_stream)?;
    println!("[Firewall] recu RecordMessage du client");

    let kcfs = session.kcfs.expect("kcfs doit etre defini");
    let fw_record = fw
        .process_record_message(client_record, &kcfs, &mut rng)
        .expect("message record invalide");

    net::send_msg(&mut server_stream, &fw_record)?;
    println!("[Firewall] message record relaye au serveur");

    Ok(())
}
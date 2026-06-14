use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

mod client;
mod firewall;
mod server;
mod crypto;

fn main() {
    let mut rng = OsRng;

    // Chaque partie choisit un secret aléatoire (un "scalaire" = un nombre mod p)
    let x = Scalar::random(&mut rng);
    let y = Scalar::random(&mut rng);

    // Calcul de la clé publique : secret * G (G = point générateur de Ristretto)
    let big_x = x * RISTRETTO_BASEPOINT_POINT;
    let big_y = y * RISTRETTO_BASEPOINT_POINT;

    // Propriété DH : x*(y*G) == y*(x*G)
    let shared_from_x = x * big_y;
    let shared_from_y = y * big_x;

    assert_eq!(shared_from_x, shared_from_y);
    println!("OK : les deux secrets partagés sont identiques !");
}
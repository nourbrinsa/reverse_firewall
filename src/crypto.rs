//! Briques cryptographiques "off-the-shelf" utilisées par le protocole.
//!
//! Ce module est complet et fonctionnel : vous n'avez normalement RIEN à
//! modifier ici. Il fournit :
//!   - des scalaires et points aléatoires sur le groupe Ristretto255 (= G dans l'article)
//!   - un chiffrement ElGamal "haché" (hashed ElGamal / ECIES) pour Enc_pkFW / Dec_skFW
//!   - les fonctions de hachage H1 et H2 (modélisées comme des oracles aléatoires)
//!   - un MAC (HMAC-SHA256)
//!   - un schéma AEAD (ChaCha20-Poly1305) utilisé comme AE.Enc / AE.Dec dans la couche record
//!
//! Convention de notation :
//!   Dans l'article, le groupe est noté multiplicativement : g^x.
//!   En Rust avec curve25519-dalek, le groupe est noté additivement : x * G.
//!   Donc "X = g^x" de l'article s'écrit ici `let big_x = x * RISTRETTO_BASEPOINT_POINT;`
//!   et "Y^x" s'écrit `x * big_y`.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

type HmacSha256 = Hmac<Sha256>;

/// Tire un scalaire aléatoire dans Zp (équivalent de `x <- Zp` dans l'article).
pub fn random_scalar(rng: &mut impl RngCore) -> Scalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// Calcule g^x, c'est-à-dire le point associé à un scalaire x.
pub fn base_point(x: &Scalar) -> RistrettoPoint {
    x * RISTRETTO_BASEPOINT_POINT
}

// ---------------------------------------------------------------------
// Chiffrement ElGamal "haché" (hashed ElGamal / ECIES), IND-CPA sous DDH+ROM.
//
// C'est l'instanciation concrète de Enc_pkFW / Dec_skFW utilisée dans
// l'article (qui suggère "El Gamal" sans préciser l'encodage).
//
// Principe : pour chiffrer un message m de 32 octets avec la clé publique
// pk = sk * G :
//   1. tirer r aléatoire, calculer R = r * G
//   2. calculer le secret partagé S = r * pk (= sk * R)
//   3. dériver une clé k = H(S) de 32 octets
//   4. le chiffré est (R, m XOR k)
//
// Pour déchiffrer avec sk :
//   1. recalculer S = sk * R
//   2. dériver k = H(S)
//   3. m = (m XOR k) XOR k
// ---------------------------------------------------------------------

/// Un chiffré ElGamal haché : (R, masque).
#[derive(Clone, Debug)]
pub struct ElGamalCiphertext {
    pub r_point: RistrettoPoint,
    pub masked: [u8; 32],
}

/// Dérive une clé symétrique de 32 octets à partir d'un élément de groupe
/// issu du handshake (kcs ou kcfs). Utilisez cette fonction pour transformer
/// kcs / kcfs (qui sont des RistrettoPoint, cf "g^(x*y)") en clés de 32 octets
/// utilisables par H1, H2, MAC, AE.Enc, etc.
pub fn kdf(p: &RistrettoPoint) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"session-key-derivation");
    hasher.update(p.compress().as_bytes());
    hasher.finalize().into()
}

/// Concatène les représentations en octets de plusieurs points, pour
/// construire le message à signer / vérifier
/// (ex : transcript = (Y, D, X^beta1, C^beta2) dans Fig. 3).
pub fn concat_points(points: &[&RistrettoPoint]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in points {
        out.extend_from_slice(p.compress().as_bytes());
    }
    out
}

/// Chiffre un message de 32 octets (typiquement les octets d'un Scalar) avec la clé publique `pk`.
pub fn elgamal_encrypt(pk: &RistrettoPoint, msg: &[u8; 32], rng: &mut impl RngCore) -> ElGamalCiphertext {
    let r = random_scalar(rng);
    let r_point = base_point(&r);
    let shared = r * pk;
    let key = kdf(&shared);

    let mut masked = [0u8; 32];
    for i in 0..32 {
        masked[i] = msg[i] ^ key[i];
    }
    ElGamalCiphertext { r_point, masked }
}

/// Déchiffre un ElGamalCiphertext avec la clé privée `sk`.
pub fn elgamal_decrypt(sk: &Scalar, ct: &ElGamalCiphertext) -> [u8; 32] {
    let shared = sk * ct.r_point;
    let key = kdf(&shared);

    let mut msg = [0u8; 32];
    for i in 0..32 {
        msg[i] = ct.masked[i] ^ key[i];
    }
    msg
}

// ---------------------------------------------------------------------
// Fonctions de hachage H1, H2 (cf Fig. 4) et MAC.
//
// H1 et H2 doivent être deux fonctions "indépendantes" du point de vue du
// modèle de l'oracle aléatoire. On les sépare simplement par un préfixe de
// domaine différent ("H1" / "H2").
// ---------------------------------------------------------------------

/// H1(input) -> 32 octets. Utilisé pour masquer le chiffré C dans la couche record.
pub fn h1(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"H1-domain");
    hasher.update(input);
    hasher.finalize().into()
}

/// H2(input) -> 32 octets. Utilisé comme clé de MAC dans la couche record.
pub fn h2(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"H2-domain");
    hasher.update(input);
    hasher.finalize().into()
}

/// MAC_k(msg) -> 32 octets (HMAC-SHA256).
pub fn mac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut h = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepte n'importe quelle taille de clé");
    h.update(msg);
    h.finalize().into_bytes().into()
}

/// Vérifie un MAC en temps constant.
pub fn mac_verify(key: &[u8; 32], msg: &[u8], tag: &[u8; 32]) -> bool {
    let expected = mac(key, msg);
    // Comparaison en temps constant pour éviter les attaques par timing.
    use subtle::ConstantTimeEq;
    expected.ct_eq(tag).into()
}

// ---------------------------------------------------------------------
// AEAD = AE.Enc / AE.Dec (cf Fig. 4), instancié avec ChaCha20-Poly1305.
//
// Le schéma de l'article est "stateful length-hiding AEAD" (stLHAE) : un état
// (compteur de séquence) est maintenu entre les appels pour générer un nonce
// différent à chaque message. Pour ce prototype, on utilise un compteur u64
// fourni explicitement par l'appelant comme nonce.
// ---------------------------------------------------------------------

/// Chiffre `plaintext` avec la clé `key` (32 octets) et le compteur `seq` comme nonce.
pub fn ae_encrypt(key: &[u8; 32], seq: u64, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.encrypt(nonce, plaintext).expect("le chiffrement ne devrait jamais échouer")
}

/// Déchiffre `ciphertext` avec la clé `key` et le compteur `seq`.
/// Retourne `Err` si l'authentification échoue (équivalent de M = perp dans Fig. 4).
pub fn ae_decrypt(key: &[u8; 32], seq: u64, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "échec de l'authentification AEAD".to_string())
}

// ---------------------------------------------------------------------
// Petites fonctions utilitaires de conversion.
// ---------------------------------------------------------------------

/// XOR de deux tableaux de 32 octets (utilisé dans Fig. 4 pour s = k1 XOR C).
pub fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_diffie_hellman_property() {
        let mut rng = OsRng;
        let x = random_scalar(&mut rng);
        let y = random_scalar(&mut rng);
        let big_x = base_point(&x);
        let big_y = base_point(&y);
        assert_eq!(x * big_y, y * big_x);
    }

    #[test]
    fn test_elgamal_roundtrip() {
        let mut rng = OsRng;
        let sk = random_scalar(&mut rng);
        let pk = base_point(&sk);
        let msg = [42u8; 32];
        let ct = elgamal_encrypt(&pk, &msg, &mut rng);
        let decrypted = elgamal_decrypt(&sk, &ct);
        assert_eq!(msg, decrypted);
    }

    #[test]
    fn test_ae_roundtrip() {
        let key = [7u8; 32];
        let plaintext = b"message secret";
        let ct = ae_encrypt(&key, 0, plaintext);
        let pt = ae_decrypt(&key, 0, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_mac_verify() {
        let key = [1u8; 32];
        let msg = b"hello";
        let tag = mac(&key, msg);
        assert!(mac_verify(&key, msg, &tag));
        assert!(!mac_verify(&key, b"hellp", &tag));
    }

    #[test]
    fn test_h1_h2_domain_separation() {
        // H1 et H2 doivent donner des résultats différents sur la même entrée :
        // c'est ce qui garantit qu'elles se comportent comme deux oracles
        // aléatoires indépendants dans la couche record (Fig. 4).
        let input = b"r || kcfs";
        assert_ne!(h1(input), h2(input));
    }

    #[test]
    fn test_ed25519_signature_roundtrip() {
        // Démonstration de la brique "Signatures Ed25519" utilisée pour
        // sigma = Sign_skS(...) côté serveur, et la vérification côté
        // client/firewall (cf Fig. 3).
        use ed25519_dalek::{Signer, SigningKey, Verifier};
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        // Le "transcript" à signer, ex : concat_points(&[&Y, &D, &X_b1, &C_b2])
        let transcript = b"transcript a signer";

        let signature = signing_key.sign(transcript);

        // La vérification doit réussir sur le bon transcript...
        assert!(verifying_key.verify(transcript, &signature).is_ok());

        // ... et échouer si le transcript a été modifié (cf rerandomisation
        // par le firewall : la signature doit rester valide sur le
        // transcript rerandomisé, mais invalide sur n'importe quel autre).
        assert!(verifying_key.verify(b"autre transcript", &signature).is_err());
    }
}

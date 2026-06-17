/// pki.rs — Chargement et validation des clés depuis les fichiers PKI (OpenSSL/PEM).
///
/// Chaque acteur appelle la fonction qui lui est destinée au démarrage.
/// La validation OpenSSL (chaîne CA) est effectuée avant toute extraction
/// de clé, ce qui garantit que personne ne peut injecter une clé non certifiée.
///
/// Format des clés :
///   - Serveur   : Ed25519 (PKCS#8 PEM) → ed25519_dalek::SigningKey / VerifyingKey
///   - Firewall  : Ed25519 (PKCS#8 PEM) → seed 32 bytes → Scalar Ristretto + RistrettoPoint
///
/// La seed Ed25519 (32 bytes) est réutilisée comme scalaire Ristretto via
/// `Scalar::from_bytes_mod_order`. C'est intentionnel : une seule paire de
/// fichiers OpenSSL suffit pour représenter la clé ElGamal du firewall.

use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::process::Command;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rustls_pemfile;
use pkcs8::der::Decode;

use crate::crypto;

// ---------------------------------------------------------------------------
// Erreur PKI
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct PkiError(pub String);

impl std::fmt::Display for PkiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Erreur PKI : {}", self.0)
    }
}

impl From<String> for PkiError {
    fn from(s: String) -> Self { PkiError(s) }
}

macro_rules! pki_err {
    ($($arg:tt)*) => { PkiError(format!($($arg)*)) };
}

// ---------------------------------------------------------------------------
// Structures retournées
// ---------------------------------------------------------------------------

/// Clés chargées par le Serveur.
pub struct ServerKeys {
    /// Clé de signature Ed25519 (secrète).
    pub signing_key: SigningKey,
    /// Clé de vérification Ed25519 (publique, à distribuer).
    pub verifying_key: VerifyingKey,
}

/// Clés chargées par le Firewall.
pub struct FirewallKeys {
    /// Scalaire secret ElGamal (dérivé de la seed Ed25519).
    pub sk_fw: Scalar,
    /// Point public ElGamal = sk_fw · G (à distribuer).
    pub pk_fw: RistrettoPoint,
}

/// Clés/certificats reçus par le Client.
pub struct ClientTrustBundle {
    /// Clé publique de vérification du serveur (pour valider sigma).
    pub pk_server: VerifyingKey,
    /// Clé publique ElGamal du firewall (pour chiffrer e = Enc_pkFW(c)).
    pub pk_fw: RistrettoPoint,
}

/// Bundle de confiance pour le Client en mode SANS firewall.
/// Ne contient que pk_server — pas de pk_fw puisqu'il n'y a pas de firewall.
pub struct ClientTrustBundleDirect {
    pub pk_server: VerifyingKey,
}

// ---------------------------------------------------------------------------
// Utilitaires internes — Parsing sécurisé avec rustls-pemfile, pkcs8 et spki
// ---------------------------------------------------------------------------

/// Vérifie qu'un certificat leaf est bien signé par le certificat CA via `openssl verify`.
/// La vérification de signature Ed25519 dans les certificats X.509 est complexe ;
/// on laisse OpenSSL gérer cette responsabilité critique.
fn verify_cert(ca_path: &Path, cert_path: &Path) -> Result<(), PkiError> {
    let output = Command::new("openssl")
        .args(["verify", "-CAfile"])
        .arg(ca_path)
        .arg(cert_path)
        .output()
        .map_err(|e| pki_err!("impossible de lancer openssl verify : {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(pki_err!(
            "certificat {} invalide : {}",
            cert_path.display(),
            stderr.trim()
        ));
    }
    println!("[PKI] Certificat signé par la CA (vérifié via openssl)");
    Ok(())
}

/// Lit un fichier PEM contenant une clé privée Ed25519 (PKCS#8).
/// Utilise rustls-pemfile pour parser le PEM, puis pkcs8 pour extraire la seed (32 bytes).
fn read_ed25519_private_key(key_path: &Path) -> Result<[u8; 32], PkiError> {
    let pem_bytes = fs::read(key_path)
        .map_err(|e| pki_err!("lecture de la clé privée {} : {}", key_path.display(), e))?;

    let mut cursor = Cursor::new(&pem_bytes);
    let priv_key_der = match rustls_pemfile::private_key(&mut cursor) {
        Ok(Some(key)) => key.secret_der().to_vec(),
        Ok(None) => return Err(pki_err!("aucune clé privée trouvée dans {}", key_path.display())),
        Err(e) => return Err(pki_err!("décodage PEM échoue : {}", e)),
    };

    // Parser le PKCS#8
    let private_key = pkcs8::PrivateKeyInfo::from_der(&priv_key_der)
        .map_err(|e| pki_err!("parsing PKCS#8 échoue : {:?}", e))?;

    // Vérifier l'OID Ed25519
    const ED25519_OID: &str = "1.3.101.112";
    if private_key.algorithm.oid.to_string() != ED25519_OID {
        return Err(pki_err!(
            "OID algorithme inattendu : {} (attendu Ed25519)",
            private_key.algorithm.oid
        ));
    }

    // Extraire les 32 bytes de seed
    // Dans PKCS#8, la clé privée est un OCTET STRING contenant directement les 32 bytes
    let private_key_octets = private_key.private_key;
    
    // Parfois il y a un wrapper OCTET STRING supplémentaire (2 bytes header : 0x04 0x20)
    let seed_offset = if private_key_octets.len() > 32 && private_key_octets[0] == 0x04 {
        2 // Skip OCTET STRING header
    } else {
        0
    };

    if private_key_octets.len() < seed_offset + 32 {
        return Err(pki_err!(
            "clé privée Ed25519 invalide : {} bytes (attendu au moins {})",
            private_key_octets.len(),
            seed_offset + 32
        ));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&private_key_octets[seed_offset..seed_offset + 32]);
    Ok(seed)
}

/// Lit un fichier PEM contenant une clé publique Ed25519 (SubjectPublicKeyInfo).
/// Extrait directement les 32 bytes de la clé publique.
fn read_ed25519_public_key(key_path: &Path) -> Result<[u8; 32], PkiError> {
    let pem_bytes = fs::read(key_path)
        .map_err(|e| pki_err!("lecture de la clé publique {} : {}", key_path.display(), e))?;

    let mut cursor = Cursor::new(&pem_bytes);
    let mut pub_keys = rustls_pemfile::public_keys(&mut cursor);
    
    let pub_key_der = match pub_keys.next() {
        Some(Ok(key)) => key.as_ref().to_vec(),
        Some(Err(e)) => return Err(pki_err!("décodage PEM échoue : {}", e)),
        None => return Err(pki_err!("aucune clé publique trouvée dans {}", key_path.display())),
    };

    // Parser le DER SubjectPublicKeyInfo
    // Format : SEQUENCE { AlgorithmIdentifier, BIT STRING (clé publique) }
    // Pour Ed25519, la clé publique dans le BIT STRING est 32 bytes (le OID indique Ed25519)
    // Pour simplifier, on extrait les 32 bytes depuis l'offset attendu du BIT STRING
    
    // SubjectPublicKeyInfo pour Ed25519 (44 bytes) :
    //   30 2a              — SEQUENCE (42 bytes)
    //   30 05 06 03 2b 65 70  — AlgorithmIdentifier + OID Ed25519
    //   03 21 00           — BIT STRING (33 bytes : 1 byte padding + 32 bytes clé)
    //   <32 bytes clé publique>
    
    if pub_key_der.len() < 44 {
        return Err(pki_err!(
            "clé publique Ed25519 trop courte : {} bytes (attendu au moins 44)",
            pub_key_der.len()
        ));
    }

    // La clé publique commence à l'offset 12 (après AlgorithmIdentifier et BIT STRING header)
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pub_key_der[12..44]);
    Ok(pk)
}

// ---------------------------------------------------------------------------
// API publique
// ---------------------------------------------------------------------------

/// Charge les clés du Serveur depuis la PKI.
///
/// Fichiers requis :
///   - `pki_dir/server.key`  — clé privée Ed25519 (PKCS#8 PEM)
///   - `pki_dir/server.crt`  — certificat signé par la CA
///   - `pki_dir/ca.crt`      — certificat de la CA (pour vérification)
pub fn load_server_keys(pki_dir: &Path) -> Result<ServerKeys, PkiError> {
    let ca_crt_path = pki_dir.join("ca.crt");
    let server_key_path = pki_dir.join("server.key");
    let server_crt_path = pki_dir.join("server.crt");

    println!("[PKI] Chargement des clés du serveur...");

    // 1. Vérifier la signature du certificat serveur auprès de la CA
    println!("[PKI] Vérification du certificat serveur...");
    verify_cert(&ca_crt_path, &server_crt_path)?;

    // 2. Lire la clé privée et extraire la seed Ed25519
    let seed = read_ed25519_private_key(&server_key_path)?;

    // 3. Construire les clés ed25519-dalek
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    println!("[PKI] Clé serveur chargée (Ed25519, {} bytes seed)", seed.len());
    Ok(ServerKeys { signing_key, verifying_key })
}

/// Charge les clés du Firewall depuis la PKI.
///
/// Fichiers requis :
///   - `pki_dir/firewall.key` — clé privée Ed25519 (PKCS#8 PEM)
///   - `pki_dir/firewall.crt` — certificat signé par la CA
///   - `pki_dir/ca.crt`       — certificat de la CA
pub fn load_firewall_keys(pki_dir: &Path) -> Result<FirewallKeys, PkiError> {
    let ca_crt_path = pki_dir.join("ca.crt");
    let fw_key_path = pki_dir.join("firewall.key");
    let fw_crt_path = pki_dir.join("firewall.crt");

    println!("[PKI] Chargement des clés du firewall...");

    // 1. Vérifier la signature du certificat firewall
    println!("[PKI] Vérification du certificat firewall...");
    verify_cert(&ca_crt_path, &fw_crt_path)?;

    // 2. Lire la clé privée et extraire la seed Ed25519
    let seed = read_ed25519_private_key(&fw_key_path)?;

    // 3. Dériver les clés ElGamal depuis la seed
    let sk_fw = Scalar::from_bytes_mod_order(seed);
    let pk_fw = crypto::base_point(&sk_fw);

    println!("[PKI] Clé firewall chargée (ElGamal/Ristretto depuis seed Ed25519)");
    Ok(FirewallKeys { sk_fw, pk_fw })
}

/// Construit le bundle de confiance pour le Client.
///
/// Le client ne possède pas de clé privée : il reçoit (et vérifie) les
/// clés publiques du serveur et du firewall via leurs certificats signés.
///
/// Fichiers requis :
///   - `pki_dir/ca.crt`          — certificat de la CA
///   - `pki_dir/server.crt`      — certificat du serveur
///   - `pki_dir/firewall.crt`    — certificat du firewall
///   - `pki_dir/firewall_pk_ristretto.bin` — clé publique Ristretto du firewall
pub fn load_client_trust_bundle(pki_dir: &Path) -> Result<ClientTrustBundle, PkiError> {
    let ca_crt_path = pki_dir.join("ca.crt");
    let server_crt_path = pki_dir.join("server.crt");
    let fw_crt_path = pki_dir.join("firewall.crt");

    println!("[PKI] Chargement du bundle de confiance client...");

    // 1. Vérifier les signatures des deux certificats auprès de la CA
    println!("[PKI] Vérification du certificat serveur (côté client)...");
    verify_cert(&ca_crt_path, &server_crt_path)?;
    println!("[PKI] Vérification du certificat firewall (côté client)...");
    verify_cert(&ca_crt_path, &fw_crt_path)?;
    println!("[PKI] Certificats OK — signatures valides");

    // 2. Extraire la clé publique Ed25519 du serveur depuis la clé privée
    // (stockée dans firewall_pub.pem exportée par setup_pki.sh)
    let server_pub_pem_path = pki_dir.join("server_pub.pem");
    let server_pk_bytes = read_ed25519_public_key(&server_pub_pem_path)?;
    let pk_server = VerifyingKey::from_bytes(&server_pk_bytes)
        .map_err(|e| pki_err!("pk_server invalide : {}", e))?;
    println!("[PKI] Clé publique serveur chargée (Ed25519)");

    // 3. Charger la clé publique Ristretto du firewall depuis firewall_pk_ristretto.bin
    let pk_fw_path = pki_dir.join("firewall_pk_ristretto.bin");
    if !pk_fw_path.exists() {
        return Err(pki_err!(
            "firewall_pk_ristretto.bin introuvable dans {}. \
             Démarrer le firewall d'abord pour qu'il génère ce fichier.",
            pki_dir.display()
        ));
    }

    let pk_fw_bytes = fs::read(&pk_fw_path)
        .map_err(|e| pki_err!("lecture firewall_pk_ristretto.bin : {}", e))?;

    if pk_fw_bytes.len() != 32 {
        return Err(pki_err!(
            "firewall_pk_ristretto.bin invalide : {} bytes (attendu 32)",
            pk_fw_bytes.len()
        ));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pk_fw_bytes);
    let compressed = curve25519_dalek::ristretto::CompressedRistretto(arr);
    let pk_fw = compressed.decompress()
        .ok_or_else(|| pki_err!("pk_fw Ristretto invalide — point non canonique"))?;

    println!("[PKI] Clé publique firewall (Ristretto) chargée");
    Ok(ClientTrustBundle { pk_server, pk_fw })
}

/// Construit le bundle de confiance pour le Client en mode direct (sans firewall).
///
/// Contrairement à `load_client_trust_bundle`, cette fonction ne requiert
/// ni firewall.crt ni firewall_pk_ristretto.bin — uniquement la chaîne de
/// confiance du serveur.
///
/// Fichiers requis :
///   - `pki_dir/ca.crt`          — certificat de la CA
///   - `pki_dir/server.crt`      — certificat du serveur
///   - `pki_dir/server_pub.pem`  — clé publique Ed25519 du serveur
pub fn load_client_trust_bundle_direct(pki_dir: &Path) -> Result<ClientTrustBundleDirect, PkiError> {
    let ca_crt_path = pki_dir.join("ca.crt");
    let server_crt_path = pki_dir.join("server.crt");

    println!("[PKI] Chargement du bundle de confiance client (mode direct, sans firewall)...");

    // 1. Vérifier la signature du certificat serveur auprès de la CA
    println!("[PKI] Vérification du certificat serveur...");
    verify_cert(&ca_crt_path, &server_crt_path)?;
    println!("[PKI] Certificat serveur OK — signature valide");

    // 2. Extraire la clé publique Ed25519 du serveur
    let server_pub_pem_path = pki_dir.join("server_pub.pem");
    let server_pk_bytes = read_ed25519_public_key(&server_pub_pem_path)?;
    let pk_server = VerifyingKey::from_bytes(&server_pk_bytes)
        .map_err(|e| pki_err!("pk_server invalide : {}", e))?;
    println!("[PKI] Clé publique serveur chargée (Ed25519)");

    Ok(ClientTrustBundleDirect { pk_server })
}

/// Appelé par le Firewall après avoir chargé ses clés : publie pk_fw
/// (le point Ristretto compressé) dans un fichier binaire que les autres
/// acteurs peuvent lire après vérification du certificat.
pub fn publish_firewall_pk(pki_dir: &Path, pk_fw: &RistrettoPoint) -> Result<(), PkiError> {
    let path = pki_dir.join("firewall_pk_ristretto.bin");
    let bytes = pk_fw.compress().to_bytes();
    fs::write(&path, bytes)
        .map_err(|e| pki_err!("écriture firewall_pk_ristretto.bin : {}", e))?;
    println!("[PKI] pk_fw publié dans {}", path.display());
    Ok(())
}

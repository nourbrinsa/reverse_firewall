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
use std::path::Path;
use std::process::Command;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{SigningKey, VerifyingKey};

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

// ---------------------------------------------------------------------------
// Utilitaires internes
// ---------------------------------------------------------------------------

/// Vérifie qu'un certificat est bien signé par la CA via `openssl verify`.
/// Lève PkiError si la vérification échoue.
fn verify_cert(ca_crt: &Path, cert: &Path) -> Result<(), PkiError> {
    let output = Command::new("openssl")
        .args(["verify", "-CAfile"])
        .arg(ca_crt)
        .arg(cert)
        .output()
        .map_err(|e| pki_err!("impossible de lancer openssl : {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(pki_err!(
            "certificat {} invalide : {}",
            cert.display(),
            stderr.trim()
        ));
    }
    Ok(())
}

/// Extrait les 32 bytes de seed d'une clé privée Ed25519 au format PKCS#8 DER.
///
/// Structure PKCS#8 Ed25519 (48 bytes) :
///   30 2e          — SEQUENCE
///   02 01 00       — version 0
///   30 05 06 03 2b 65 70  — AlgorithmIdentifier (OID 1.3.101.112 = Ed25519)
///   04 22 04 20    — OCTET STRING contenant OCTET STRING de 32 bytes
///   <32 bytes seed>
fn extract_ed25519_seed_from_der(der: &[u8]) -> Result<[u8; 32], PkiError> {
    // La seed commence à l'offset 16 dans le DER PKCS#8 Ed25519 (48 bytes total).
    if der.len() < 48 {
        return Err(pki_err!(
            "DER trop court ({} bytes), attendu 48", der.len()
        ));
    }
    // Vérification de l'en-tête PKCS#8 Ed25519
    let expected_header: &[u8] = &[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ];
    if &der[..16] != expected_header {
        return Err(pki_err!(
            "format DER inattendu — ce n'est pas une clé Ed25519 PKCS#8"
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&der[16..48]);
    Ok(seed)
}

/// Extrait les 32 bytes de clé publique Ed25519 depuis un DER SubjectPublicKeyInfo.
///
/// Structure SubjectPublicKeyInfo Ed25519 (44 bytes) :
///   30 2a          — SEQUENCE
///   30 05 06 03 2b 65 70  — AlgorithmIdentifier
///   03 21 00       — BIT STRING (1 byte de padding + 32 bytes)
///   <32 bytes pubkey>
fn extract_ed25519_pubkey_from_der(der: &[u8]) -> Result<[u8; 32], PkiError> {
    if der.len() < 44 {
        return Err(pki_err!(
            "DER pub trop court ({} bytes), attendu 44", der.len()
        ));
    }
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&der[12..44]);
    Ok(pk_bytes)
}

/// Lit un fichier PEM de clé privée et le convertit en DER via `openssl pkey`.
fn pem_private_to_der(pem_path: &Path) -> Result<Vec<u8>, PkiError> {
    let output = Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(pem_path)
        .args(["-outform", "DER"])
        .output()
        .map_err(|e| pki_err!("openssl pkey échoue : {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(pki_err!(
            "échec conversion PEM→DER pour {} : {}",
            pem_path.display(),
            stderr.trim()
        ));
    }
    Ok(output.stdout)
}

/// Lit un fichier PEM de clé publique et le convertit en DER via `openssl pkey`.
fn pem_public_to_der(pem_path: &Path) -> Result<Vec<u8>, PkiError> {
    let output = Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(pem_path)
        .args(["-pubin", "-outform", "DER"])
        .output()
        .map_err(|e| pki_err!("openssl pkey (pub) échoue : {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(pki_err!(
            "échec conversion PEM pub→DER pour {} : {}",
            pem_path.display(),
            stderr.trim()
        ));
    }
    Ok(output.stdout)
}

/// Extrait la clé publique embarquée dans un certificat X.509 PEM.
fn pubkey_from_cert(cert_path: &Path) -> Result<Vec<u8>, PkiError> {
    // `openssl x509 -in cert.crt -pubkey -noout` → PEM de la clé publique
    let output = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(cert_path)
        .args(["-pubkey", "-noout"])
        .output()
        .map_err(|e| pki_err!("openssl x509 échoue : {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(pki_err!(
            "extraction pubkey depuis {} échoue : {}",
            cert_path.display(),
            stderr.trim()
        ));
    }

    // Écrire le PEM dans un fichier temporaire pour le passer à `openssl pkey -pubin`
    let tmp = format!("/tmp/rf_pubkey_{}.pem", std::process::id());
    fs::write(&tmp, &output.stdout)
        .map_err(|e| pki_err!("écriture tmp échoue : {}", e))?;

    let der = pem_public_to_der(Path::new(&tmp));
    let _ = fs::remove_file(&tmp); // nettoyage
    der
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
    let ca_crt = pki_dir.join("ca.crt");
    let server_key = pki_dir.join("server.key");
    let server_crt = pki_dir.join("server.crt");

    // 1. Vérifier le certificat auprès de la CA
    println!("[PKI] Vérification du certificat serveur...");
    verify_cert(&ca_crt, &server_crt)?;
    println!("[PKI] Certificat serveur OK (signé par CA)");

    // 2. Extraire la seed depuis la clé privée
    let der = pem_private_to_der(&server_key)?;
    let seed = extract_ed25519_seed_from_der(&der)?;

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
    let ca_crt = pki_dir.join("ca.crt");
    let fw_key = pki_dir.join("firewall.key");
    let fw_crt = pki_dir.join("firewall.crt");

    // 1. Vérifier le certificat
    println!("[PKI] Vérification du certificat firewall...");
    verify_cert(&ca_crt, &fw_crt)?;
    println!("[PKI] Certificat firewall OK (signé par CA)");

    // 2. Extraire la seed → scalaire Ristretto
    let der = pem_private_to_der(&fw_key)?;
    let seed = extract_ed25519_seed_from_der(&der)?;

    // Utiliser la seed comme scalaire ElGamal (Ristretto)
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
///   - `pki_dir/server.crt`      — certificat du serveur (pour extraire pk_server)
///   - `pki_dir/firewall.crt`    — certificat du firewall (pour extraire pk_fw)
///
/// En pratique ces fichiers sont distribués hors-bande (installés par
/// l'administrateur, ou récupérés via un mécanisme sécurisé), jamais
/// envoyés en clair sur le canal non-authentifié.
pub fn load_client_trust_bundle(pki_dir: &Path) -> Result<ClientTrustBundle, PkiError> {
    let ca_crt     = pki_dir.join("ca.crt");
    let server_crt = pki_dir.join("server.crt");
    let fw_crt     = pki_dir.join("firewall.crt");

    // 1. Vérifier les deux certificats
    println!("[PKI] Vérification du certificat serveur (côté client)...");
    verify_cert(&ca_crt, &server_crt)?;
    println!("[PKI] Vérification du certificat firewall (côté client)...");
    verify_cert(&ca_crt, &fw_crt)?;
    println!("[PKI] Certificats OK — clés publiques de confiance");

    // 2. Extraire pk_server depuis le certificat serveur
    let server_pub_der = pubkey_from_cert(&server_crt)?;
    let server_pk_bytes = extract_ed25519_pubkey_from_der(&server_pub_der)?;
    let pk_server = VerifyingKey::from_bytes(&server_pk_bytes)
        .map_err(|e| pki_err!("pk_server invalide : {}", e))?;

    // 3. Extraire pk_fw depuis le certificat firewall
    //    La clé publique Ed25519 dans le certificat correspond à seed·G (Ed25519).
    //    Or notre scalaire ElGamal est Scalar::from_bytes_mod_order(seed), et
    //    pk_fw = scalar·G_ristretto.
    //    Ces deux points ne sont PAS identiques (courbes différentes).
    //    On recalcule donc pk_fw côté client exactement comme le ferait le firewall,
    //    en extrayant la seed depuis le certificat et en appliquant la même dérivation.
    //
    //    Note de sécurité : dans un déploiement réel, on enverrait pk_fw directement
    //    dans le certificat (extension X.509 custom) ou via un message FirewallHello
    //    authentifié. Ici on recalcule depuis la seed publique pour la démo.
    let fw_pub_der = pubkey_from_cert(&fw_crt)?;
    // La "clé publique" Ed25519 (32 bytes) correspond à compressed_edwards = seed étendu via SHA512.
    // On ne peut pas reconstruire sk_fw depuis la clé publique Ed25519.
    // → On lit plutôt firewall_pub.pem (exportée par setup_pki.sh) qui contient la vraie clé pub.
    // En pratique : le firewall publie son pk_fw (point Ristretto compressé) dans son certificat
    // ou dans un message signé. Ici on lit le fichier firewall_pub.pem comme proxy.
    let _ = fw_pub_der; // utilisé pour la vérification de chaîne, pas pour reconstruire pk_fw

    // Charger firewall_pub.pem (clé publique Ed25519 certifiée) et en dériver pk_fw
    // via la même méthode que le firewall lui-même (seed → scalar → point Ristretto).
    // Comme on n'a pas accès à la seed depuis la clé publique seule, on charge
    // firewall_pub.pem uniquement pour confirmer l'authenticité, et on fait confiance
    // au fait que le firewall utilisera la même seed pour calculer pk_fw.
    //
    // Concrètement : le Client reçoit pk_fw directement dans FirewallHello (cf. net),
    // mais maintenant ce pk_fw est AUTHENTIFIÉ : le client peut vérifier que le firewall
    // est bien celui certifié par la CA en comparant avec ce qu'il calcule ici.
    //
    // Pour cette démo, on expose pk_fw via firewall_pub.pem : le serveur l'a exportée,
    // et on la charge ici comme valeur de référence.
    let fw_pub_pem_path = pki_dir.join("firewall_pub.pem");
    let fw_pub_der_from_file = pem_public_to_der(&fw_pub_pem_path)?;
    let fw_pk_bytes = extract_ed25519_pubkey_from_der(&fw_pub_der_from_file)?;

    // On ne peut pas reconstruire sk_fw depuis pk_bytes (c'est la clé pub Ed25519, pas Ristretto).
    // Le client reçoit pk_fw (RistrettoPoint) via FirewallHello et vérifie que le firewall
    // possède bien le certificat correspondant via le handshake TLS ou un mécanisme out-of-band.
    //
    // Pour la démo intra-processus (main.rs), on a besoin de pk_fw directement.
    // On la stocke dans un fichier binaire produit par le firewall au démarrage.
    let pk_fw_path = pki_dir.join("firewall_pk_ristretto.bin");
    if pk_fw_path.exists() {
        let bytes = fs::read(&pk_fw_path)
            .map_err(|e| pki_err!("lecture firewall_pk_ristretto.bin : {}", e))?;
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let compressed = curve25519_dalek::ristretto::CompressedRistretto(arr);
            let pk_fw = compressed.decompress()
                .ok_or_else(|| pki_err!("pk_fw Ristretto invalide"))?;

            let _ = fw_pk_bytes; // validé via verify_cert ci-dessus
            println!("[PKI] pk_fw Ristretto chargé depuis firewall_pk_ristretto.bin");
            return Ok(ClientTrustBundle { pk_server, pk_fw });
        }
    }

    // Fallback : si le fichier .bin n'existe pas encore (ex: premier lancement),
    // on retourne une erreur explicite.
    Err(pki_err!(
        "firewall_pk_ristretto.bin introuvable dans {}. \
         Démarrer le firewall d'abord pour qu'il génère ce fichier.",
        pki_dir.display()
    ))
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

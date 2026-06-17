use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Verifier, VerifyingKey};
use rand::RngCore;

use crate::crypto;
use crate::messages::{ClientInit, FirewallToClient, FirewallToServer, RecordMessage, ServerResponse};

pub struct Firewall {
    sk_fw: Scalar,
    pub pk_fw: RistrettoPoint,
    pk_server: VerifyingKey,
}

pub struct FirewallSession {
    alpha1: Scalar,
    alpha2: Scalar,
    c: Scalar,
    big_x: RistrettoPoint,
    big_c: RistrettoPoint,
    pub kcfs: Option<[u8; 32]>,
    rf: [u8; 32],               // aléa R_f choisi par le firewall
    nc_tilde: [u8; 32],         // nonce du client rerandomisé par le firewall
}

impl Firewall {
    /// Constructeur original : génère une paire de clés aléatoire.
    /// Utilisé uniquement par main.rs (test local sans PKI).
    pub fn new(pk_server: VerifyingKey, rng: &mut impl RngCore) -> Self {
        let sk_fw = crypto::random_scalar(rng);
        let pk_fw = crypto::base_point(&sk_fw);
        Firewall { sk_fw, pk_fw, pk_server }
    }

    /// Constructeur PKI : charge les clés depuis les fichiers générés par
    /// setup_pki.sh. Appelé par firewall_bin.rs au démarrage.
    ///
    /// pk_server est transmis par le serveur via ServerHello au moment
    /// de la connexion (et vérifié par la CA côté client via load_client_trust_bundle).
    pub fn from_pki(
        pki_dir: &std::path::Path,
        pk_server: VerifyingKey,
    ) -> Result<Self, crate::pki::PkiError> {
        let keys = crate::pki::load_firewall_keys(pki_dir)?;

        // Publier pk_fw dans un fichier .bin que le client pourra lire
        // après avoir vérifié le certificat du firewall.
        crate::pki::publish_firewall_pk(pki_dir, &keys.pk_fw)?;

        Ok(Firewall {
            sk_fw: keys.sk_fw,
            pk_fw: keys.pk_fw,
            pk_server,
        })
    }

    pub fn process_client_init(
        &self,
        msg: ClientInit,
        rng: &mut impl RngCore,
    ) -> Result<(FirewallToServer, FirewallSession), String> {
        let c_bytes = crypto::elgamal_decrypt(&self.sk_fw, &msg.enc_c);
        let c = Scalar::from_bytes_mod_order(c_bytes);

        if crypto::base_point(&c) != msg.big_c {
            return Err("incohérence détectée : g^c != C".to_string());
        }

        let alpha1 = crypto::random_scalar(rng);
        let alpha2 = crypto::random_scalar(rng);

        let mut rf = [0u8; 32];
        rng.fill_bytes(&mut rf);
        let nc_tilde = crypto::xor_32(&msg.nc, &rf);    // Nc_tilde = N_c XOR R_f

        let big_x_tilde = alpha1 * msg.big_x;
        let big_c_tilde = alpha2 * msg.big_c;

        let c_tilde = c * alpha2;
        let enc_c_tilde = crypto::elgamal_encrypt(&self.pk_fw, &c_tilde.to_bytes(), rng);

        let fw_to_server = FirewallToServer { nc_tilde, big_x_tilde, big_c_tilde, enc_c_tilde };
        let session = FirewallSession {
            alpha1, alpha2, c,
            big_x: msg.big_x,
            big_c: msg.big_c,
            kcfs: None,
            rf, nc_tilde,
        };

        Ok((fw_to_server, session))
    }

    pub fn process_server_response(
        &self,
        msg: ServerResponse,
        session: &mut FirewallSession,
    ) -> Result<FirewallToClient, String> {
        let gamma1 = session.alpha1 * msg.beta1;
        let gamma2 = session.alpha2 * msg.beta2;

        let x_gamma1 = gamma1 * session.big_x;
        let c_gamma2 = gamma2 * session.big_c;

        let r = crypto::xor_32(&session.rf, &msg.rs);   // R = R_f XOR R_s
        let nc_tilde_xor_rs = crypto::xor_32(&session.nc_tilde, &msg.rs);

        // Transcription côté serveur (pour vérifier le MAC du serveur)
        let mut server_transcript = Vec::new();
        server_transcript.extend_from_slice(&nc_tilde_xor_rs);
        server_transcript.extend_from_slice(&msg.ns);
        server_transcript.extend_from_slice(&crypto::concat_points(&[&msg.big_y, &msg.big_d, &x_gamma1, &c_gamma2]));

        self.pk_server
            .verify(&server_transcript, &msg.signature)
            .map_err(|_| "signature du serveur invalide".to_string())?;

        let dh_kcfs_point = (session.c * gamma2) * msg.big_d;
        let prk_kcfs = crypto::hkdf_extract(&[], crypto::kdf(&dh_kcfs_point).as_ref());
        let handshake_key = crypto::hkdf_expand(&prk_kcfs, b"handshake_mac");

        let expected_mac = crypto::mac(&handshake_key, &server_transcript);
        if expected_mac[..] != msg.mac_finished[..] {
            return Err("MAC finished du serveur est invalide".to_string());
        }

        // Transcription côté client
        let nc_xor_r = crypto::xor_32(&crypto::xor_32(&session.nc_tilde, &session.rf), &r); // Reconstruit N_c XOR R
        let mut client_transcript = Vec::new();
        client_transcript.extend_from_slice(&nc_xor_r);
        client_transcript.extend_from_slice(&msg.ns);
        client_transcript.extend_from_slice(&crypto::concat_points(&[&msg.big_y, &msg.big_d, &x_gamma1, &c_gamma2]));

        let mac_finished_client = crypto::mac(&handshake_key, &client_transcript).try_into().unwrap();

        // HKDF pour kcfs
        session.kcfs = Some(crypto::hkdf_expand(&prk_kcfs, b"session_kcfs"));

        Ok(FirewallToClient {
            ns: msg.ns, r,
            big_y: msg.big_y,
            big_d: msg.big_d,
            gamma1,
            gamma2,
            signature: msg.signature,
            mac_finished: mac_finished_client,
        })
    }

    pub fn process_record_message(
        &self,
        msg: RecordMessage,
        kcfs: &[u8; 32],
        rng: &mut impl RngCore,
    ) -> Result<RecordMessage, String> {
        let r_kcfs: Vec<u8> = msg.r.iter().chain(kcfs.iter()).copied().collect();
        let k1 = crypto::h1(&r_kcfs);
        let k2 = crypto::h2(&r_kcfs);

        let mac_input: Vec<u8> = msg.r.iter().chain(msg.s.iter()).copied().collect();
        if !crypto::mac_verify(&k2, &mac_input, &msg.t) {
            return Err("MAC invalide".to_string());
        }

        let big_c: Vec<u8> = msg.s.iter()
            .enumerate()
            .map(|(i, &b)| b ^ k1[i % 32])
            .collect();

        let mut r_tilde = [0u8; 32];
        rng.fill_bytes(&mut r_tilde);

        let r_tilde_kcfs: Vec<u8> = r_tilde.iter().chain(kcfs.iter()).copied().collect();
        let k1_tilde = crypto::h1(&r_tilde_kcfs);
        let k2_tilde = crypto::h2(&r_tilde_kcfs);

        let s_tilde: Vec<u8> = big_c.iter()
            .enumerate()
            .map(|(i, &b)| b ^ k1_tilde[i % 32])
            .collect();

        let t_tilde_input: Vec<u8> = r_tilde.iter().chain(s_tilde.iter()).copied().collect();
        let t_tilde = crypto::mac(&k2_tilde, &t_tilde_input);

        Ok(RecordMessage { r: r_tilde, s: s_tilde, t: t_tilde })
    }
}

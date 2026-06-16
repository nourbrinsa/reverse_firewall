use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;

use crate::crypto;
use crate::messages::{FirewallToServer, RecordMessage, ServerResponse};

pub struct Server {
    sk: SigningKey,
    pub pk: VerifyingKey,
    pub kcs:  Option<[u8; 32]>,
    pub kcfs: Option<[u8; 32]>,
}

impl Server {
    /// Constructeur original : génère une paire de clés aléatoire.
    /// Utilisé uniquement par main.rs (test local sans PKI).
    pub fn new(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let sk = SigningKey::from_bytes(&bytes);
        let pk = sk.verifying_key();
        Server { sk, pk, kcs: None, kcfs: None }
    }

    /// Constructeur PKI : charge les clés depuis les fichiers générés par
    /// setup_pki.sh. Appelé par server_bin.rs au démarrage.
    pub fn from_pki(pki_dir: &std::path::Path) -> Result<Self, crate::pki::PkiError> {
        let keys = crate::pki::load_server_keys(pki_dir)?;
        Ok(Server {
            pk: keys.verifying_key,
            sk: keys.signing_key,
            kcs:  None,
            kcfs: None,
        })
    }

    pub fn process_firewall_init(
        &mut self,
        msg: FirewallToServer,
        rng: &mut impl RngCore,
    ) -> ServerResponse {
        let y     = crypto::random_scalar(rng);
        let d     = crypto::random_scalar(rng);
        let beta1 = crypto::random_scalar(rng);
        let beta2 = crypto::random_scalar(rng);

        let big_y = crypto::base_point(&y);
        let big_d = crypto::base_point(&d);

        let x_tilde_beta1 = beta1 * msg.big_x_tilde;
        let c_tilde_beta2 = beta2 * msg.big_c_tilde;

        let transcript = crypto::concat_points(
            &[&big_y, &big_d, &x_tilde_beta1, &c_tilde_beta2]
        );
        let signature = self.sk.sign(&transcript);

        let kcs_point  = (y * beta1) * msg.big_x_tilde;
        let kcfs_point = (d * beta2) * msg.big_c_tilde;

        self.kcs  = Some(crypto::kdf(&kcs_point));
        self.kcfs = Some(crypto::kdf(&kcfs_point));

        ServerResponse { signature, big_y, big_d, beta1, beta2 }
    }

    pub fn process_record_message(
        &mut self,
        msg: RecordMessage,
        seq: u64,
    ) -> Result<Vec<u8>, String> {
        let kcs  = self.kcs.unwrap();
        let kcfs = self.kcfs.unwrap();

        let r_kcfs: Vec<u8> = msg.r.iter().chain(kcfs.iter()).copied().collect();
        let k1_tilde = crypto::h1(&r_kcfs);
        let k2_tilde = crypto::h2(&r_kcfs);

        let mac_input: Vec<u8> = msg.r.iter().chain(msg.s.iter()).copied().collect();
        if !crypto::mac_verify(&k2_tilde, &mac_input, &msg.t) {
            return Err("MAC invalide : message rejeté".to_string());
        }

        let c_bytes: Vec<u8> = msg.s.iter()
            .enumerate()
            .map(|(i, &b)| b ^ k1_tilde[i % 32])
            .collect();

        crypto::ae_decrypt(&kcs, seq, &c_bytes)
    }
}

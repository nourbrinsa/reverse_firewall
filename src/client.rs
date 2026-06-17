use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Verifier, VerifyingKey};
use rand::RngCore;

use crate::crypto;
use crate::messages::{ClientInit, FirewallToClient, ClientInitDirect, ServerResponseDirect};

pub struct Client {
    /// Secrets ephemeres x et c (cf "x, c <- Zp" dans Fig. 3).
    x: Scalar,
    c: Scalar,

    /// Cle publique du pare-feu, utilisee pour Enc_pkFW.
    pk_fw: RistrettoPoint,

    /// Cle publique de signature du serveur, pour verifier sigma.
    pk_server: VerifyingKey,

    /// Cles de session, calculees a la fin du handshake (Some apres `finalize`).
    pub kcs: Option<[u8; 32]>,
    pub kcfs: Option<[u8; 32]>,
}

impl Client {
    /// Cree un nouveau client avec des secrets x, c frais.
    pub fn new(pk_fw: RistrettoPoint, pk_server: VerifyingKey, rng: &mut impl RngCore) -> Self {
        let x = crypto::random_scalar(rng);
        let c = crypto::random_scalar(rng);

        Client {
            x,
            c,
            pk_fw,
            pk_server,
            kcs: None,
            kcfs: None,
        }
    }

    /// Construit le premier message envoye au Firewall : (X, C, e).
    pub fn init_message(&self, rng: &mut impl RngCore) -> ClientInit {
        // Etape 1 : X = g^x
        let big_x = crypto::base_point(&self.x);

        // Etape 2 : C = g^c
        let big_c = crypto::base_point(&self.c);

        // Etape 3 : e = ElGamal(pkFW, c·G)
        // On chiffre le point C lui-meme (= c·G), le firewall pourra
        // verifier apres dechiffrement que le resultat est bien egal a C.
        let enc_c = crypto::elgamal_encrypt(&self.pk_fw, &self.c.to_bytes(), rng);

        ClientInit {
            big_x,
            big_c,
            enc_c,
        }
    }

    /// Construit le message direct vers le Serveur : (X, C), sans e.
    /// Reference : Fig. 2, premiere fleche Client -> Server (sans firewall).
    pub fn init_message_direct(&self) -> ClientInitDirect {
        // Etape 1 : X = g^x
        let big_x = crypto::base_point(&self.x);

        // Etape 2 : C = g^c
        let big_c = crypto::base_point(&self.c);

        ClientInitDirect {
            big_x,
            big_c,
        }
    }

    /// Traite la reponse finale du Firewall : (sigma, Y, D, gamma1, gamma2).
    pub fn finalize(&mut self, msg: FirewallToClient) -> Result<(), String> {
        // Etape 1 : reconstruire le transcript signe (Y, D, X^gamma1, C^gamma2)
        // X^gamma1 = g^(x*gamma1) car X = g^x
        let x_gamma1 = crypto::base_point(&(self.x * msg.gamma1));
        // C^gamma2 = g^(c*gamma2) car C = g^c
        let c_gamma2 = crypto::base_point(&(self.c * msg.gamma2));

        let transcript_bytes =
            crypto::concat_points(&[&msg.big_y, &msg.big_d, &x_gamma1, &c_gamma2]);

        // Etape 2 : verifier la signature
        // Si invalide -> abort (cf Fig. 3 "Else: abort")
        self.pk_server
            .verify(&transcript_bytes, &msg.signature)
            .map_err(|e| format!("Signature invalide : {}", e))?;

        // Etape 3 : calculer kcs et kcfs
        // kcs  = Y^(x*gamma1)
        let kcs_point = (self.x * msg.gamma1) * msg.big_y;
        // kcfs = D^(c*gamma2)
        let kcfs_point = (self.c * msg.gamma2) * msg.big_d;

        self.kcs = Some(crypto::kdf(&kcs_point));
        self.kcfs = Some(crypto::kdf(&kcfs_point));

        Ok(())
    }

    /// Traite la reponse directe du Serveur : (sigma, Y, D, beta1, beta2).
    /// Reference : Fig. 2, derniere fleche Server -> Client.
    /// Ne calcule que kcs ; kcfs reste None car il n'y a pas de firewall.
    pub fn finalize_direct(&mut self, msg: ServerResponseDirect) -> Result<(), String> {
        let x_beta1 = crypto::base_point(&(self.x * msg.beta1));
        let c_beta2  = crypto::base_point(&(self.c * msg.beta2));

        let transcript = crypto::concat_points(&[&msg.big_y, &msg.big_d, &x_beta1, &c_beta2]);

        self.pk_server
            .verify(&transcript, &msg.signature)
            .map_err(|e| format!("Signature invalide : {}", e))?;

        let kcs_point = (self.x * msg.beta1) * msg.big_y;
        self.kcs = Some(crypto::kdf(&kcs_point));
        // kcfs reste None

        Ok(())
    }
}

# Reverse Firewall - Squelette du projet

## Repartition du travail

| Fichier       | Responsable | Statut                                          |
| ------------- | ----------- | ----------------------------------------------- |
| `crypto.rs`   | N           | Implemente + teste                              |
| `messages.rs` | Commun      | Complet, ne pas modifier (sauf si besoin avere) |
| `client.rs`   | Personne A  | TODO                                            |
| `firewall.rs` | N           | TODO                                            |
| `server.rs`   | Personne B  | TODO                                            |
| `main.rs`     | Commun      | Squelette d'orchestration fourni                |

## Le contrat d'interface (a respecter par tous)

Tout le monde compile dès le premier jour grace aux `todo!()`. Le contrat
ci-dessous DOIT rester stable : si vous changez une signature, prevenez les
autres (ca cassera leur code a la compilation).

### Cles de session, partout dans le code

```rust
pub kcs:  Option<[u8; 32]>,
pub kcfs: Option<[u8; 32]>,
```

Toujours des `[u8; 32]`, obtenus via `crypto::kdf(&point)`. Jamais de
`RistrettoPoint` ou de `Scalar` brut en dehors du handshake.

### Fonctions de `crypto.rs` disponibles pour tous (`use crate::crypto;`)

```rust
crypto::random_scalar(rng) -> Scalar
crypto::base_point(&scalar) -> RistrettoPoint          // g^x

crypto::elgamal_encrypt(&pk, &msg32, rng) -> ElGamalCiphertext
crypto::elgamal_decrypt(&sk, &ciphertext) -> [u8; 32]

crypto::kdf(&point) -> [u8; 32]                        // group element -> cle 32 octets
crypto::concat_points(&[&p1, &p2, ...]) -> Vec<u8>     // pour construire un transcript a signer

crypto::h1(&bytes) -> [u8; 32]
crypto::h2(&bytes) -> [u8; 32]
crypto::mac(&key32, &msg) -> [u8; 32]
crypto::mac_verify(&key32, &msg, &tag) -> bool

crypto::ae_encrypt(&key32, seq: u64, &plaintext) -> Vec<u8>
crypto::ae_decrypt(&key32, seq: u64, &ciphertext) -> Result<Vec<u8>, String>
crypto::xor32(&a32, &b32) -> [u8; 32]
```

### Types de messages (`messages.rs`, ne changent pas)

`ClientInit`, `FirewallToServer`, `ServerResponse`, `FirewallToClient`,
`RecordMessage` -- cf commentaires dans le fichier, ils correspondent
chacun a une fleche de la Fig. 3 / Fig. 4 de l'article.

### Fonctions publiques de chaque struct (le "contrat")

```rust
// client.rs
Client::new(pk_fw: RistrettoPoint, pk_server: VerifyingKey, rng) -> Client
client.init_message(rng) -> ClientInit
client.finalize(msg: FirewallToClient) -> Result<(), String>
client.kcs / client.kcfs : Option<[u8; 32]>

// firewall.rs
Firewall::new(pk_server: VerifyingKey, rng) -> Firewall
firewall.pk_fw : RistrettoPoint   (public, le client en a besoin)
firewall.process_client_init(msg: ClientInit, rng) -> Result<(FirewallToServer, FirewallSession), String>
firewall.process_server_response(msg: ServerResponse, session: &mut FirewallSession) -> Result<FirewallToClient, String>
firewall.process_record_message(msg: RecordMessage, kcfs: &[u8;32], rng) -> Result<RecordMessage, String>
session.kcfs : Option<[u8; 32]>

// server.rs
Server::new(rng) -> Server
server.pk : VerifyingKey   (public, client et firewall en ont besoin)
server.process_firewall_init(msg: FirewallToServer, rng) -> ServerResponse
server.process_record_message(msg: RecordMessage, seq: u64) -> Result<Vec<u8>, String>
server.kcs / server.kcfs : Option<[u8; 32]>
```

## Comment travailler

1. Chacun complete les `todo!()` de son fichier en suivant les commentaires.
2. `cargo build` doit toujours reussir (meme avec des `todo!()` restants
   ailleurs : ca compile, ca ne panique qu'a l'execution de cette fonction precise).
3. Pour tester votre partie isolement avant que les autres aient fini,
   ecrivez des tests unitaires dans votre fichier (`#[cfg(test)] mod tests { ... }`),
   comme dans `crypto.rs`.
4. `main.rs` ne pourra s'executer sans panic que lorsque les 3 parties
   (client/firewall/server) sont terminees -- c'est le test d'integration final.

## Lancer

```bash
cargo test     # tests unitaires de chaque module
cargo run      # simulation complete (handshake + record layer)
```

## Solve git commits conflicts when somebody else already pushed

First, if you have already committed the code, revert it

```bash
git reset HEAD~
```

Then stash your changes

```bash
git stash push -m <stash_message> --include-untracked
```

Now you can pull your changes

Then pop the stash:

```bash
git stash pop
```

And finally, you can commit your changes without any conflict

# Reverse Firewall

A Rust implementation of a reverse firewall cryptographic protocol for secure communication between clients and servers.

## Project Overview

This project implements a three-party cryptographic protocol involving:
- **Client**: Initiates secure communication
- **Firewall**: Intermediary that processes encrypted messages
- **Server**: Receives and responds to requests

The implementation uses Ristretto255 elliptic curves, Ed25519 signatures, and ChaCha20-Poly1305 AEAD encryption.

## Setup

### Prerequisites

- Rust 1.70+ (with Cargo)
- Linux, macOS, or Windows environment

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/nourbrinsa/reverse_firewall.git
   cd reverse_firewall
   ```

2. **Install dependencies**
   Dependencies are managed by Cargo and defined in `Cargo.toml`. They will be automatically downloaded when you run any cargo command.

3. **Verify the setup**
   ```bash
   cargo --version
   rustc --version
   ```

## Available Commands

### Build Commands

**`cargo build`**
- Compiles the project in debug mode
- Slower compilation, faster execution during development
- Output: `target/debug/reverse_firewall`

**`cargo build --release`**
- Compiles the project in release mode with optimizations
- Slower compilation, faster execution in production
- Output: `target/release/reverse_firewall`

### Testing Commands

**`cargo test`**
- Runs all unit and integration tests in the project
- Tests are defined in each module using `#[cfg(test)] mod tests { ... }`
- Useful for validating individual component implementations before integration testing

**`cargo test -- --nocapture`**
- Runs tests with output printed to console
- Useful for debugging test failures

**`cargo test <module_name>`**
- Runs tests for a specific module (e.g., `cargo test crypto`)
- Helpful when testing individual components

### Execution Commands

**`cargo run`**
- Compiles and executes the complete simulation
- Runs the full handshake protocol and record layer exchange
- This will only run without panicking once all three components (client/firewall/server) are fully implemented

**`cargo run --release`**
- Compiles and runs with optimizations enabled
- Faster execution than debug mode

### Development Commands

**`cargo check`**
- Quickly checks if the code compiles without generating a binary
- Faster than `cargo build`, useful for rapid feedback during development

**`cargo clean`**
- Removes all build artifacts in the `target/` directory
- Useful when you need a fresh build or to save disk space

**`cargo fmt`**
- Formats code according to Rust conventions (requires `rustfmt`)
- Can be used with `--check` to verify formatting without modifying files

**`cargo clippy`**
- Runs the Rust linter to catch common mistakes and suggest improvements (requires `clippy`)

## Project Structure

| File | Responsibility | Status |
| --- | --- | --- |
| `crypto.rs` | Cryptographic primitives (encryption, key derivation, hashing) | Core utilities |
| `messages.rs` | Message type definitions (immutable protocol contracts) | Protocol specification |
| `client.rs` | Client-side protocol implementation | Development |
| `firewall.rs` | Firewall-side protocol implementation | Development |
| `server.rs` | Server-side protocol implementation | Development |
| `main.rs` | Integration orchestration and simulation | Integration test |

## Code Organization

### Public Crypto Functions

All cryptographic operations are accessed through the `crypto` module:

```rust
crypto::random_scalar(rng) -> Scalar
crypto::base_point(&scalar) -> RistrettoPoint
crypto::elgamal_encrypt(&pk, &msg32, rng) -> ElGamalCiphertext
crypto::elgamal_decrypt(&sk, &ciphertext) -> [u8; 32]
crypto::kdf(&point) -> [u8; 32]
crypto::concat_points(&[&p1, &p2, ...]) -> Vec<u8>
crypto::h1(&bytes) -> [u8; 32]
crypto::h2(&bytes) -> [u8; 32]
crypto::mac(&key32, &msg) -> [u8; 32]
crypto::mac_verify(&key32, &msg, &tag) -> bool
crypto::ae_encrypt(&key32, seq: u64, &plaintext) -> Vec<u8>
crypto::ae_decrypt(&key32, seq: u64, &ciphertext) -> Result<Vec<u8>, String>
crypto::xor32(&a32, &b32) -> [u8; 32]
```

### Session Keys

Session keys are consistently represented as optional 32-byte arrays throughout the codebase:

```rust
pub kcs:  Option<[u8; 32]>,   // Client-Server session key
pub kcfs: Option<[u8; 32]>,   // Client-Firewall-Server session key
```

## Fixing Git Commit Conflicts When Somebody Else Pushed

If you have uncommitted changes and someone else has already pushed changes that conflict with yours:

### Step 1: Revert any committed changes

```bash
git reset HEAD~
```

This moves your HEAD back one commit but keeps your changes in the working directory.

### Step 2: Stash your changes

```bash
git stash push -m <stash_message> --include-untracked
```

This temporarily saves your changes, including untracked files. Replace `<stash_message>` with a descriptive message about your changes.

### Step 3: Pull the latest changes

```bash
git pull
```

Fetch and integrate the latest changes from the remote repository.

### Step 4: Restore your changes

```bash
git stash pop
```

This retrieves your stashed changes and applies them on top of the newly pulled code.

### Step 5: Commit without conflicts

```bash
git add .
git commit -m "Your commit message"
git push
```

You can now commit and push your changes without merge conflicts.

## Dependencies

- **curve25519-dalek** (4.x): Ristretto255 elliptic curve group and scalar arithmetic
- **ed25519-dalek** (2.1.1): Ed25519 digital signatures and verification
- **sha2** (0.10): SHA-256/512 hash functions for H1, H2 oracles
- **hmac** (0.12): HMAC for message authentication codes
- **chacha20poly1305** (0.10): AEAD encryption/decryption
- **rand** (0.8): Cryptographic random number generation
- **subtle** (2.x): Constant-time comparisons for MAC verification
- **serde** (1.x) & **bincode** (1.3): Serialization/deserialization
- **zeroize** (1.7.0): Secure memory zeroing for sensitive data
- **base64ct** (1.6.0): Base64 encoding/decoding

## License

This project is part of a cryptographic protocol implementation exercise.

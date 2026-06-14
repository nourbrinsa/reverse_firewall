# Reverse Firewall

A group project implementing a **reverse firewall** in Rust, using elliptic-curve Diffie-Hellman (ECDH) key exchange over the Ristretto255 curve (`curve25519-dalek`) for cryptographic operations.

The project is structured around four main components:
- **`client`** – the client-side logic
- **`server`** – the server-side logic
- **`firewall`** – the reverse firewall that sits between client and server
- **`crypto`** – shared cryptographic primitives (ECDH via Ristretto255)

---

## Prerequisites: Setting Up Rust on Linux

### 1. Install Rust (via `rustup`)

`rustup` is the official Rust toolchain installer. Run the following command in your terminal:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the on-screen prompts (press `1` to proceed with the default installation).

### 2. Load Rust into your current shell session

After installation, reload your shell environment so the `cargo` and `rustc` commands become available:

```bash
source $HOME/.cargo/env
```

> **Tip:** This line is automatically added to your `~/.bashrc` / `~/.zshrc` by the installer, so future terminal sessions will have Rust available automatically.

### 3. Verify the installation

```bash
rustc --version
cargo --version
```

You should see version numbers printed for both tools (e.g., `rustc 1.78.0` and `cargo 1.78.0`).

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/nourbrinsa/reverse_firewall.git
cd reverse_firewall
```

### 2. Build the project

```bash
cargo build
```

This will download all dependencies (listed in `Cargo.toml`) and compile the project. The first build may take a minute.

### 3. Run the project

```bash
cargo run
```

### 4. Run in release mode (optimized)

```bash
cargo build --release
cargo run --release
```

---

## Project Structure

```
reverse_firewall/
├── Cargo.toml        # Project manifest & dependencies
├── Cargo.lock        # Locked dependency versions
└── src/
    ├── main.rs       # Entry point
    ├── client.rs     # Client logic
    ├── server.rs     # Server logic
    ├── firewall.rs   # Reverse firewall logic
    └── crypto.rs     # Cryptographic primitives (ECDH / Ristretto255)
```

---

## Dependencies

| Crate | Version | Purpose |
|---|---|---|
| [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek) | 4 | Elliptic-curve arithmetic (Ristretto255) |
| [`rand`](https://crates.io/crates/rand) | 0.8 | Cryptographically secure random number generation |

---

## Useful Cargo Commands

| Command | Description |
|---|---|
| `cargo build` | Compile the project (debug mode) |
| `cargo run` | Compile and run the project |
| `cargo test` | Run all tests |
| `cargo check` | Fast syntax/type check without producing a binary |
| `cargo clippy` | Run the Rust linter for code quality suggestions |
| `cargo fmt` | Auto-format all source files |
| `cargo doc --open` | Generate and open the project documentation |

---

## Troubleshooting

- **`cargo: command not found`** — Run `source $HOME/.cargo/env` or open a new terminal.
- **Linker errors on Debian/Ubuntu/Kali** — Install the C linker: `sudo apt install build-essential`
- **Outdated Rust** — Update your toolchain with: `rustup update`

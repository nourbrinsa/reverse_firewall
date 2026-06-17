# Reverse Firewall deployment commands

Run the deployment script from the RF machine only.

## 1. On all three machines

```bash
cd /path/to/reverse_firewall
cargo build --bins
```

## 2. On RF only

```bash
cd /path/to/reverse_firewall
chmod +x setup_pki.sh deploy_reverse_firewall_3nodes.sh
./deploy_reverse_firewall_3nodes.sh --create-env
nano .env
chmod 600 .env
./deploy_reverse_firewall_3nodes.sh --check-config
./deploy_reverse_firewall_3nodes.sh --clean-runtime
./deploy_reverse_firewall_3nodes.sh --all
```

## 3. On Client only, after RF script finishes

```bash
cd /path/to/reverse_firewall
PKI_DIR=pki CLIENT_ADDR='<RF_LAN_IP>:8081' cargo run --bin client_bin
```

The script prints the exact client command at the end.

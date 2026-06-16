#!/usr/bin/env bash
# =============================================================================
# setup_pki.sh — Génération de la PKI pour reverse-firewall
#
# Produit dans le dossier pki/ :
#   ca.key / ca.crt          — Autorité de certification racine (auto-signée)
#   server.key / server.crt  — Paire Ed25519 du serveur, signée par la CA
#   firewall.key / fw.crt    — Paire Ed25519 du firewall, signée par la CA
#
# Les binaires Rust chargent ces fichiers au démarrage via pki.rs.
# =============================================================================

set -euo pipefail

PKI_DIR="${PKI_DIR:-pki}"

echo "=== Génération de la PKI dans ./${PKI_DIR}/ ==="
mkdir -p "$PKI_DIR"

# ---------------------------------------------------------------------------
# 1. Autorité de certification (CA)
# ---------------------------------------------------------------------------
echo "[1/5] Génération de la clé privée CA (Ed25519)..."
openssl genpkey -algorithm Ed25519 -out "$PKI_DIR/ca.key"

echo "[2/5] Génération du certificat CA (auto-signé, 10 ans)..."
openssl req -new -x509 \
  -key "$PKI_DIR/ca.key" \
  -out "$PKI_DIR/ca.crt" \
  -days 3650 \
  -subj "/CN=ReverseFirewall-CA/O=Demo/OU=PKI"

# ---------------------------------------------------------------------------
# 2. Certificat du Serveur
# ---------------------------------------------------------------------------
echo "[3/5] Génération et certification de la clé serveur..."
openssl genpkey -algorithm Ed25519 -out "$PKI_DIR/server.key"

openssl req -new \
  -key "$PKI_DIR/server.key" \
  -out "$PKI_DIR/server.csr" \
  -subj "/CN=server/O=Demo/OU=Server"

openssl x509 -req \
  -in "$PKI_DIR/server.csr" \
  -CA "$PKI_DIR/ca.crt" \
  -CAkey "$PKI_DIR/ca.key" \
  -CAcreateserial \
  -out "$PKI_DIR/server.crt" \
  -days 365

# Exporter la clé publique seule (distribuée au client et au firewall)
openssl pkey -in "$PKI_DIR/server.key" -pubout -out "$PKI_DIR/server_pub.pem"

# ---------------------------------------------------------------------------
# 3. Certificat du Firewall
# ---------------------------------------------------------------------------
echo "[4/5] Génération et certification de la clé firewall..."
openssl genpkey -algorithm Ed25519 -out "$PKI_DIR/firewall.key"

openssl req -new \
  -key "$PKI_DIR/firewall.key" \
  -out "$PKI_DIR/firewall.csr" \
  -subj "/CN=firewall/O=Demo/OU=Firewall"

openssl x509 -req \
  -in "$PKI_DIR/firewall.csr" \
  -CA "$PKI_DIR/ca.crt" \
  -CAkey "$PKI_DIR/ca.key" \
  -CAcreateserial \
  -out "$PKI_DIR/firewall.crt" \
  -days 365

# Exporter la clé publique seule (distribuée au client)
openssl pkey -in "$PKI_DIR/firewall.key" -pubout -out "$PKI_DIR/firewall_pub.pem"

# ---------------------------------------------------------------------------
# 4. Vérification des chaînes
# ---------------------------------------------------------------------------
echo "[5/5] Vérification des certificats..."
openssl verify -CAfile "$PKI_DIR/ca.crt" "$PKI_DIR/server.crt"
openssl verify -CAfile "$PKI_DIR/ca.crt" "$PKI_DIR/firewall.crt"

# Nettoyage des CSR intermédiaires
rm -f "$PKI_DIR/server.csr" "$PKI_DIR/firewall.csr"

echo ""
echo "=== PKI générée avec succès ==="
echo ""
echo "Fichiers produits :"
ls -1 "$PKI_DIR/"
echo ""
echo "Distribution des fichiers :"
echo "  Serveur   ← pki/server.key  pki/server.crt  pki/ca.crt"
echo "  Firewall  ← pki/firewall.key pki/firewall.crt pki/ca.crt"
echo "  Client    ← pki/server_pub.pem pki/firewall_pub.pem pki/ca.crt"
echo ""
echo "Variable d'environnement optionnelle : PKI_DIR=<chemin> ./setup_pki.sh"
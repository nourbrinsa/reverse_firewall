#!/usr/bin/env bash
# =============================================================================
# deploy_reverse_firewall_3nodes_env.sh
# Déploiement PKI + lancement ordonné pour Reverse Firewall sur 3 machines Linux.
#
# Hypothèse recommandée:
#   - exécuter ce script depuis la machine RF;
#   - RF joue temporairement le rôle de machine de provisioning PKI;
#   - le code Rust existe déjà sur les 3 machines dans les ch&ns définis dans .env.
# =============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"

# ------------------------------- Helpers -------------------------------------
log() { printf '\n\033[1;34m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '\n\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
err() { printf '\n\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    err "Commande manquante: $1"
    err "Installez-la puis relancez. Exemple Debian/Ubuntu/Kali: sudo apt update && sudo apt install -y openssh-client openssl"
    exit 1
  }
}

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    err "Variable manquante dans .env: $name"
    exit 1
  fi
}

load_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    err "Fichier .env introuvable: $ENV_FILE"
    exit 1
  fi

  # .env est un fichier local de confiance. On le source pour supporter les guillemets et $HOME.
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a

  local env_mode
  env_mode="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE" 2>/dev/null || true)"
  if [[ -n "$env_mode" && "$env_mode" != "600" ]]; then
    warn "$ENV_FILE a les permissions $env_mode. Recommandé: chmod 600 '$ENV_FILE'"
  fi
}

load_config() {
  load_env

  # Mandatory machine-specific values.
  require_var SERVER_USER
  require_var SERVER_HOST
  require_var CLIENT_USER
  require_var CLIENT_HOST
  require_var SERVER_LAN_IP
  require_var RF_LAN_IP
  require_var SERVER_APP_DIR
  require_var CLIENT_APP_DIR
  require_var RF_APP_DIR

  # Non-sensitive defaults.
  SERVER_BIN="${SERVER_BIN:-server_bin}"
  FIREWALL_BIN="${FIREWALL_BIN:-firewall_bin}"
  CLIENT_BIN="${CLIENT_BIN:-client_bin}"

  SERVER_PORT="${SERVER_PORT:-9090}"
  FIREWALL_PORT="${FIREWALL_PORT:-8081}"

  SERVER_BIND_ADDR="${SERVER_BIND_ADDR:-0.0.0.0:${SERVER_PORT}}"
  FIREWALL_BIND_ADDR="${FIREWALL_BIND_ADDR:-0.0.0.0:${FIREWALL_PORT}}"
  FIREWALL_SERVER_ADDR="${FIREWALL_SERVER_ADDR:-${SERVER_LAN_IP}:${SERVER_PORT}}"
  CLIENT_ADDR="${CLIENT_ADDR:-${RF_LAN_IP}:${FIREWALL_PORT}}"

  SSH_KEY="${SSH_KEY:-$HOME/.ssh/rf_deploy_ed25519}"
  SSH_PORT="${SSH_PORT:-22}"

  DEPLOY_ROOT="${DEPLOY_ROOT:-$HOME/.reverse_firewall_deploy}"
  FULL_PKI_DIR="$DEPLOY_ROOT/full_pki"
  STAGE_DIR="$DEPLOY_ROOT/stage"
  CA_PRIVATE_DIR="$DEPLOY_ROOT/ca_private_DO_NOT_SHARE"
}

show_config_safe() {
  log "Configuration chargée depuis: $ENV_FILE"
  cat <<CONFIG
Server SSH target      : ${SERVER_USER}@${SERVER_HOST}
Client SSH target      : ${CLIENT_USER}@${CLIENT_HOST}
RF project directory   : ${RF_APP_DIR}
Server project dir     : ${SERVER_APP_DIR}
Client project dir     : ${CLIENT_APP_DIR}
Server runtime address : ${FIREWALL_SERVER_ADDR}
Client target address  : ${CLIENT_ADDR}
SSH key path on RF     : ${SSH_KEY}
Deployment staging     : ${DEPLOY_ROOT}
CONFIG
}

ssh_base() {
  ssh -p "$SSH_PORT" -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new "$@"
}

scp_base() {
  scp -P "$SSH_PORT" -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new "$@"
}

remote_mkdir_secure() {
  local target="$1" dir="$2"
  ssh_base "$target" "mkdir -p '$dir/pki' '$dir/logs' && chmod 700 '$dir/pki'"
}

remote_install_pki_file() {
  local target="$1" local_file="$2" remote_file="$3" mode="$4"
  scp_base "$local_file" "$target:$remote_file"
  ssh_base "$target" "chmod '$mode' '$remote_file'"
}

local_install_pki_file() {
  local src="$1" dst="$2" mode="$3"
  install -m "$mode" "$src" "$dst"
}

usage() {
  cat <<USAGE
Usage:
  ./$(basename "$0") --check-config
  ./$(basename "$0") --init-ssh
  ./$(basename "$0") --deploy-pki
  ./$(basename "$0") --run-demo
  ./$(basename "$0") --all
  ./$(basename "$0") --clean-runtime

Configuration:
  3) ./$(basename "$0") --check-config
  4) ./$(basename "$0") --all

You can use another env file with:
  ENV_FILE=/path/to/my.env ./$(basename "$0") --all
USAGE
}

check_config() {
  require_cmd ssh
  require_cmd scp
  show_config_safe

  [[ -f "$SSH_KEY" ]] || warn "Clé SSH privée introuvable: $SSH_KEY. Lancez --init-ssh ou créez-la avec ssh-keygen."
  [[ -d "$RF_APP_DIR" ]] || { err "RF_APP_DIR introuvable: $RF_APP_DIR"; exit 1; }
  [[ -x "$RF_APP_DIR/setup_pki.sh" ]] || { err "setup_pki.sh introuvable ou non exécutable dans $RF_APP_DIR"; exit 1; }

  log "Test SSH Server"
  ssh_base "${SERVER_USER}@${SERVER_HOST}" "hostname && whoami && test -d '$SERVER_APP_DIR' && echo 'SERVER_APP_DIR OK'"

  log "Test SSH Client"
  ssh_base "${CLIENT_USER}@${CLIENT_HOST}" "hostname && whoami && test -d '$CLIENT_APP_DIR' && echo 'CLIENT_APP_DIR OK'"

  log "Configuration OK"
}

# ----------------------------- SSH bootstrap ---------------------------------
init_ssh() {
  require_cmd ssh-keygen
  require_cmd ssh-copy-id
  require_cmd ssh

  log "Initialisation SSH depuis RF vers Server et Client"

  mkdir -p "$(dirname "$SSH_KEY")"
  chmod 700 "$(dirname "$SSH_KEY")"

  if [[ ! -f "$SSH_KEY" ]]; then
    ssh-keygen -t ed25519 -a 100 -f "$SSH_KEY" -C "reverse-firewall-deploy-$(hostname)-$(date +%Y%m%d)"
    chmod 600 "$SSH_KEY"
    chmod 644 "$SSH_KEY.pub"
  else
    warn "La clé existe déjà: $SSH_KEY"
  fi

  log "Installation de la clé sur Server: ${SERVER_USER}@${SERVER_HOST}"
  ssh-copy-id -p "$SSH_PORT" -i "$SSH_KEY.pub" "${SERVER_USER}@${SERVER_HOST}"

  log "Installation de la clé sur Client: ${CLIENT_USER}@${CLIENT_HOST}"
  ssh-copy-id -p "$SSH_PORT" -i "$SSH_KEY.pub" "${CLIENT_USER}@${CLIENT_HOST}"

  log "Test SSH Server"
  ssh_base "${SERVER_USER}@${SERVER_HOST}" "hostname && whoami"

  log "Test SSH Client"
  ssh_base "${CLIENT_USER}@${CLIENT_HOST}" "hostname && whoami"

  log "SSH OK"
}

# ----------------------------- PKI deploy ------------------------------------
generate_pki_once() {
  require_cmd openssl
  require_cmd scp
  require_cmd ssh

  [[ -d "$RF_APP_DIR" ]] || { err "RF_APP_DIR introuvable: $RF_APP_DIR"; exit 1; }
  [[ -x "$RF_APP_DIR/setup_pki.sh" ]] || { err "setup_pki.sh introuvable ou non exécutable dans $RF_APP_DIR"; exit 1; }

  log "Génération de la PKI une seule fois sur la machine RF"
  rm -rf "$FULL_PKI_DIR" "$STAGE_DIR"
  mkdir -p "$FULL_PKI_DIR" "$STAGE_DIR" "$CA_PRIVATE_DIR"
  chmod 700 "$DEPLOY_ROOT" "$FULL_PKI_DIR" "$STAGE_DIR" "$CA_PRIVATE_DIR"

  (cd "$RF_APP_DIR" && PKI_DIR="$FULL_PKI_DIR" ./setup_pki.sh)

  chmod 600 "$FULL_PKI_DIR"/*.key
  chmod 644 "$FULL_PKI_DIR"/*.crt "$FULL_PKI_DIR"/*_pub.pem 2>/dev/null || true

  # Garder ca.key hors du dossier runtime. Aucun acteur n'en a besoin pour exécuter le protocole.
  mv "$FULL_PKI_DIR/ca.key" "$CA_PRIVATE_DIR/ca.key"
  chmod 600 "$CA_PRIVATE_DIR/ca.key"

  log "Création des bundles PKI par rôle"
  mkdir -p "$STAGE_DIR/server/pki" "$STAGE_DIR/firewall/pki" "$STAGE_DIR/client/pki"
  chmod 700 "$STAGE_DIR"/*/pki

  # Serveur: uniquement sa clé privée + son certificat + CA publique.
  install -m 644 "$FULL_PKI_DIR/ca.crt" "$STAGE_DIR/server/pki/ca.crt"
  install -m 644 "$FULL_PKI_DIR/server.crt" "$STAGE_DIR/server/pki/server.crt"
  install -m 600 "$FULL_PKI_DIR/server.key" "$STAGE_DIR/server/pki/server.key"

  # Firewall: uniquement sa clé privée + son certificat + CA publique.
  install -m 644 "$FULL_PKI_DIR/ca.crt" "$STAGE_DIR/firewall/pki/ca.crt"
  install -m 644 "$FULL_PKI_DIR/firewall.crt" "$STAGE_DIR/firewall/pki/firewall.crt"
  install -m 600 "$FULL_PKI_DIR/firewall.key" "$STAGE_DIR/firewall/pki/firewall.key"
  install -m 644 "$FULL_PKI_DIR/server.crt" "$STAGE_DIR/firewall/pki/server.crt"
  install -m 644 "$FULL_PKI_DIR/server_pub.pem" "$STAGE_DIR/firewall/pki/server_pub.pem"

  # Client: aucun secret. Il reçoit les certificats et la clé publique serveur.
  install -m 644 "$FULL_PKI_DIR/ca.crt" "$STAGE_DIR/client/pki/ca.crt"
  install -m 644 "$FULL_PKI_DIR/server.crt" "$STAGE_DIR/client/pki/server.crt"
  install -m 644 "$FULL_PKI_DIR/firewall.crt" "$STAGE_DIR/client/pki/firewall.crt"
  install -m 644 "$FULL_PKI_DIR/server_pub.pem" "$STAGE_DIR/client/pki/server_pub.pem"

  log "PKI générée. ca.key est conservée ici, hors runtime: $CA_PRIVATE_DIR/ca.key"
}

deploy_pki() {
  generate_pki_once

  local server_target="${SERVER_USER}@${SERVER_HOST}"
  local client_target="${CLIENT_USER}@${CLIENT_HOST}"

  log "Déploiement PKI vers Server"
  remote_mkdir_secure "$server_target" "$SERVER_APP_DIR"
  ssh_base "$server_target" "rm -rf '$SERVER_APP_DIR/pki'/*"
  remote_install_pki_file "$server_target" "$STAGE_DIR/server/pki/ca.crt" "$SERVER_APP_DIR/pki/ca.crt" 644
  remote_install_pki_file "$server_target" "$STAGE_DIR/server/pki/server.crt" "$SERVER_APP_DIR/pki/server.crt" 644
  remote_install_pki_file "$server_target" "$STAGE_DIR/server/pki/server.key" "$SERVER_APP_DIR/pki/server.key" 600

  log "Déploiement PKI locale vers RF"
  mkdir -p "$RF_APP_DIR/pki" "$RF_APP_DIR/logs"
  chmod 700 "$RF_APP_DIR/pki"
  rm -rf "$RF_APP_DIR/pki"/*
  local_install_pki_file "$STAGE_DIR/firewall/pki/ca.crt" "$RF_APP_DIR/pki/ca.crt" 644
  local_install_pki_file "$STAGE_DIR/firewall/pki/firewall.crt" "$RF_APP_DIR/pki/firewall.crt" 644
  local_install_pki_file "$STAGE_DIR/firewall/pki/firewall.key" "$RF_APP_DIR/pki/firewall.key" 600
  local_install_pki_file "$STAGE_DIR/firewall/pki/server.crt" "$RF_APP_DIR/pki/server.crt" 644
  local_install_pki_file "$STAGE_DIR/firewall/pki/server_pub.pem" "$RF_APP_DIR/pki/server_pub.pem" 644

  log "Déploiement PKI vers Client"
  remote_mkdir_secure "$client_target" "$CLIENT_APP_DIR"
  ssh_base "$client_target" "rm -rf '$CLIENT_APP_DIR/pki'/*"
  remote_install_pki_file "$client_target" "$STAGE_DIR/client/pki/ca.crt" "$CLIENT_APP_DIR/pki/ca.crt" 644
  remote_install_pki_file "$client_target" "$STAGE_DIR/client/pki/server.crt" "$CLIENT_APP_DIR/pki/server.crt" 644
  remote_install_pki_file "$client_target" "$STAGE_DIR/client/pki/firewall.crt" "$CLIENT_APP_DIR/pki/firewall.crt" 644
  remote_install_pki_file "$client_target" "$STAGE_DIR/client/pki/server_pub.pem" "$CLIENT_APP_DIR/pki/server_pub.pem" 644

  log "Distribution PKI terminée"
}

# ----------------------------- Runtime ---------------------------------------
start_server() {
  local server_target="${SERVER_USER}@${SERVER_HOST}"
  log "Démarrage du serveur sur ${server_target}"

  ssh_base "$server_target" "
    cd '$SERVER_APP_DIR'
    mkdir -p logs
    pkill -f 'cargo run --bin ${SERVER_BIN}' 2>/dev/null || true
    nohup env PKI_DIR=pki SERVER_ADDR='${SERVER_BIND_ADDR}' cargo run --bin '${SERVER_BIN}' \
      > logs/server.log 2>&1 < /dev/null &
    echo \$! > logs/server.pid
  "

  sleep 2
  log "Log serveur récent:"
  ssh_base "$server_target" "tail -n 20 '$SERVER_APP_DIR/logs/server.log' || true"
}

start_firewall() {
  log "Démarrage du RF local"

  cd "$RF_APP_DIR"
  mkdir -p logs
  pkill -f "cargo run --bin ${FIREWALL_BIN}" 2>/dev/null || true

  nohup env PKI_DIR=pki \
    FIREWALL_LISTEN="$FIREWALL_BIND_ADDR" \
    FIREWALL_SERVER_ADDR="$FIREWALL_SERVER_ADDR" \
    cargo run --bin "$FIREWALL_BIN" \
    > logs/firewall.log 2>&1 < /dev/null &
  echo $! > logs/firewall.pid

  log "Attente de génération de pki/firewall_pk_ristretto.bin par le RF"
  for _ in {1..40}; do
    if [[ -s "$RF_APP_DIR/pki/firewall_pk_ristretto.bin" ]]; then
      chmod 644 "$RF_APP_DIR/pki/firewall_pk_ristretto.bin"
      log "firewall_pk_ristretto.bin généré"
      return 0
    fi
    sleep 0.5
  done

  err "Le RF n'a pas généré firewall_pk_ristretto.bin. Dernières lignes du log:"
  tail -n 80 "$RF_APP_DIR/logs/firewall.log" || true
  exit 1
}

send_firewall_pk_to_client() {
  local client_target="${CLIENT_USER}@${CLIENT_HOST}"
  log "Envoi de firewall_pk_ristretto.bin vers Client"
  remote_install_pki_file "$client_target" \
    "$RF_APP_DIR/pki/firewall_pk_ristretto.bin" \
    "$CLIENT_APP_DIR/pki/firewall_pk_ristretto.bin" \
    644
}

run_demo() {
  start_server
  start_firewall
  send_firewall_pk_to_client

  log "Déploiement runtime prêt"
  cat <<NEXT

À lancer sur la machine Client pour garder un terminal interactif :

  cd '$CLIENT_APP_DIR'
  PKI_DIR=pki CLIENT_ADDR='$CLIENT_ADDR' cargo run --bin '$CLIENT_BIN'

Ou depuis cette machine RF, si vous voulez piloter le client via SSH :

  ssh -p '$SSH_PORT' -i '$SSH_KEY' ${CLIENT_USER}@${CLIENT_HOST} "cd '$CLIENT_APP_DIR' && PKI_DIR=pki CLIENT_ADDR='$CLIENT_ADDR' cargo run --bin '$CLIENT_BIN'"

Logs utiles :
  Server : ssh -p '$SSH_PORT' -i '$SSH_KEY' ${SERVER_USER}@${SERVER_HOST} "tail -f '$SERVER_APP_DIR/logs/server.log'"
  RF     : tail -f '$RF_APP_DIR/logs/firewall.log'
NEXT
}

clean_runtime() {
  local server_target="${SERVER_USER}@${SERVER_HOST}"
  log "Arrêt des processus server/firewall lancés par cargo run"
  ssh_base "$server_target" "pkill -f 'cargo run --bin ${SERVER_BIN}' 2>/dev/null || true"
  pkill -f "cargo run --bin ${FIREWALL_BIN}" 2>/dev/null || true
  log "Runtime nettoyé"
}

# ------------------------------- Main ----------------------------------------
main() {
  case "${1:-}" in
    --create-env)
      create_env_files
      ;;
    -h|--help|"")
      usage
      ;;
    --check-config)
      load_config
      check_config
      ;;
    --init-ssh)
      load_config
      init_ssh
      ;;
    --deploy-pki)
      load_config
      deploy_pki
      ;;
    --run-demo)
      load_config
      run_demo
      ;;
    --all)
      load_config
      deploy_pki
      run_demo
      ;;
    --clean-runtime)
      load_config
      clean_runtime
      ;;
    *)
      err "Option inconnue: $1"
      usage
      exit 1
      ;;
  esac
}

main "$@"
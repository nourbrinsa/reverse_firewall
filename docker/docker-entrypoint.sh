#!/bin/sh
set -e

echo "[entrypoint] APP_NAME=$APP_NAME"

if [ "$APP_NAME" = "firewall_bin" ]; then
    echo "[entrypoint] running deploy script..."
    ./deploy_reverse_firewall_3nodes.sh --all
fi

# For server and client, wait for the pki directory to be populated
if [ "$APP_NAME" = "server_bin" ] || [ "$APP_NAME" = "client_bin" ]; then
    echo "[entrypoint] waiting for pki directory to be populated..."
    while [ ! -d "/bin/pki" ] || [ -z "$(ls -A /bin/pki 2>/dev/null)" ]; do
        echo "[entrypoint] pki not ready yet, retrying in 2s..."
        sleep 2
    done
    echo "[entrypoint] pki directory found and populated, proceeding"
fi

exec "$@"
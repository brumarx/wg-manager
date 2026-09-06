#!/bin/bash
# WireGuard Manager — instalação automática completa
# Gere os peers WireGuard de um router MikroTik (RouterOS 7+) via SSH — o
# WireGuard não corre nesta máquina, corre no router. Este script instala só
# o painel web.
#
# Uso: sudo bash install.sh
#
# Variáveis de ambiente opcionais (se não definidas, o script pergunta):
#   MIKROTIK_HOST   IP do MikroTik (ex: 192.168.1.1)
#   MIKROTIK_USER   utilizador SSH do MikroTik
#   MIKROTIK_PASS   password desse utilizador
#   WG_HOST         IP público ou hostname pelo qual os clientes VPN ligam
#   LAN_NETWORK     rede local para o modo "só LAN" (default: 192.168.1.0/24)
#   WG_MANAGER_PORT porta da UI (default: primeira livre a partir de 8080)
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}==>${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[ERRO]${NC} $1"; exit 1; }

[ "$EUID" -ne 0 ] && error "Corre como root: sudo bash install.sh"

INSTALL_DIR="/opt/wg-manager"
SERVICE="wg-manager"

# --- Perguntar dados do MikroTik se não vierem por variável de ambiente ---
if [ -z "$MIKROTIK_HOST" ]; then
    read -rp "IP do MikroTik na LAN (ex: 192.168.1.1): " MIKROTIK_HOST
fi
if [ -z "$MIKROTIK_USER" ]; then
    read -rp "Utilizador SSH do MikroTik: " MIKROTIK_USER
fi
if [ -z "$MIKROTIK_PASS" ]; then
    read -rsp "Password desse utilizador: " MIKROTIK_PASS
    echo
fi
[ -z "$MIKROTIK_HOST" ] && error "MIKROTIK_HOST é obrigatório."
[ -z "$MIKROTIK_USER" ] && error "MIKROTIK_USER é obrigatório."
[ -z "$MIKROTIK_PASS" ] && error "MIKROTIK_PASS é obrigatório."

LAN_NETWORK="${LAN_NETWORK:-192.168.1.0/24}"
PUBLIC_IP="${WG_HOST:-$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')}"

# --- Testar ligação SSH ao MikroTik antes de continuar ---
info "A testar SSH ao MikroTik ($MIKROTIK_USER@$MIKROTIK_HOST)..."
if ! command -v sshpass >/dev/null; then
    apt-get install -y -qq sshpass 2>/dev/null || true
fi
if ! SSHPASS="$MIKROTIK_PASS" sshpass -e ssh -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=6 "${MIKROTIK_USER}@${MIKROTIK_HOST}" ':put "ok"' 2>/dev/null | grep -q ok; then
    error "Não consegui ligar por SSH ao MikroTik. Confirma IP/utilizador/password e que o serviço SSH está ativo lá (/ip service enable ssh)."
fi
info "SSH ao MikroTik OK."

# --- Parar serviço anterior se existir ---
if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    warn "Serviço anterior encontrado — a parar..."
    systemctl stop "$SERVICE"
fi

# --- Encontrar porta livre a partir de 8080 ---
find_free_port() {
    local port=8080
    while ss -tlnp | grep -q ":${port} "; do
        echo -e "${YELLOW}[!]${NC} Porta $port ocupada, a tentar $((port+1))..." >&2
        port=$((port + 1))
    done
    echo "$port"
}
PORT="${WG_MANAGER_PORT:-$(find_free_port)}"

info "IP público: $PUBLIC_IP"
info "Porto da UI: $PORT"

# --- Dependências ---
# wireguard-tools só é preciso para gerar chaves (wg genkey/pubkey/genpsk) —
# o WireGuard em si não corre aqui, corre no MikroTik.
info "A verificar dependências..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip wireguard-tools curl sshpass 2>/dev/null || true

# --- Copiar ficheiros ---
info "A instalar em $INSTALL_DIR..."
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
# Limpar instalação anterior mas preservar base de dados
if [ -f "$INSTALL_DIR/wg_manager.db" ]; then
    warn "Base de dados existente preservada."
    cp "$INSTALL_DIR/wg_manager.db" /tmp/wg_manager_backup.db
fi
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -r "$SRC_DIR/." "$INSTALL_DIR/"
# Restaurar base de dados se havia
if [ -f /tmp/wg_manager_backup.db ]; then
    cp /tmp/wg_manager_backup.db "$INSTALL_DIR/wg_manager.db"
    rm /tmp/wg_manager_backup.db
fi

# --- Ambiente virtual Python ---
info "A criar ambiente virtual..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"

# --- Ficheiro de segredos (fora do systemd unit, permissões restritas) ---
info "A guardar credenciais do MikroTik..."
cat > "$INSTALL_DIR/mikrotik.env" << EOF
MIKROTIK_PASS=${MIKROTIK_PASS}
EOF
chmod 600 "$INSTALL_DIR/mikrotik.env"

# --- Base de dados e importação de peers já existentes no MikroTik ---
info "A inicializar base de dados..."
MIKROTIK_HOST="$MIKROTIK_HOST" MIKROTIK_USER="$MIKROTIK_USER" MIKROTIK_PASS="$MIKROTIK_PASS" \
"$INSTALL_DIR/venv/bin/python" - << PYEOF
import sys, os
sys.path.insert(0, '$INSTALL_DIR')
os.chdir('$INSTALL_DIR')
from app import init_db, migrate_db, detect_interface, import_peers_from_conf
init_db()
migrate_db()
print('  Base de dados OK')
iface = detect_interface()
count, err = import_peers_from_conf(iface)
if err:
    print(f'  Aviso importação: {err}')
elif count > 0:
    print(f'  {count} peer(s) importado(s) do MikroTik')
else:
    print('  Nenhum peer novo para importar (cria a interface WireGuard no MikroTik primeiro, se ainda não existir)')
PYEOF

# --- Permissões ---
chmod 750 "$INSTALL_DIR"
chmod 640 "$INSTALL_DIR/wg_manager.db" 2>/dev/null || true

# --- Serviço systemd ---
info "A configurar serviço systemd..."
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

mkdir -p /etc/systemd/system/${SERVICE}.service.d
cat > /etc/systemd/system/${SERVICE}.service.d/override.conf << EOF
[Service]
Environment=MIKROTIK_HOST=${MIKROTIK_HOST}
Environment=MIKROTIK_USER=${MIKROTIK_USER}
EnvironmentFile=${INSTALL_DIR}/mikrotik.env
EOF

cat > /etc/systemd/system/${SERVICE}.service << EOF
[Unit]
Description=WireGuard Manager Web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment=WG_HOST=${PUBLIC_IP}
Environment=LAN_NETWORK=${LAN_NETWORK}
Environment=SECRET_KEY=${SECRET_KEY}
Environment=PORT=${PORT}
ExecStart=${INSTALL_DIR}/venv/bin/python app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"

# --- Verificar resultado ---
sleep 3
if systemctl is-active --quiet "$SERVICE"; then
    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  WireGuard Manager instalado com sucesso!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "  URL local:    ${GREEN}http://localhost:${PORT}${NC}"
    echo -e "  URL na LAN:   ${GREEN}http://$(hostname -I | awk '{print $1}'):${PORT}${NC}"
    echo ""
    echo -e "  Na primeira visita cria a conta de administrador."
    echo -e "  (Opcional) Para notificações por Telegram, acrescenta a"
    echo -e "  ${INSTALL_DIR}/mikrotik.env: TELEGRAM_TOKEN=... e TELEGRAM_CHAT_ID=..."
    echo ""
    echo -e "  Logs:    sudo journalctl -u ${SERVICE} -f"
    echo -e "  Estado:  sudo systemctl status ${SERVICE}"
    echo -e "  Parar:   sudo systemctl stop ${SERVICE}"
    echo ""
else
    error "Serviço não iniciou. Logs:\n$(journalctl -u $SERVICE --no-pager -n 30)"
fi

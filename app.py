import os
import glob
import re
import socket
import sqlite3
import subprocess
import secrets
import ipaddress
import io
import base64
import time
from functools import wraps
from datetime import datetime

import qrcode
from flask import (Flask, render_template, request, redirect,
                   url_for, session, send_file, flash, abort, jsonify,
                   Response, stream_with_context)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))


@app.template_filter('fmt_bytes')
def fmt_bytes(n):
    n = int(n or 0)
    if n == 0:
        return '—'
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024:
            return f'{n:.1f} {unit}' if unit != 'B' else f'{n} B'
        n /= 1024
    return f'{n:.1f} PB'


@app.template_filter('ts_ago')
def ts_ago(ts):
    ts = int(ts or 0)
    if not ts:
        return 'Nunca'
    diff = int(time.time()) - ts
    if diff < 60:
        return 'agora mesmo'
    if diff < 3600:
        return f'{diff // 60} min atrás'
    if diff < 86400:
        return f'{diff // 3600}h atrás'
    return f'{diff // 86400}d atrás'

DB_PATH = os.path.join(os.path.dirname(__file__), 'wg_manager.db')
WG_DIR = '/etc/wireguard'
PUBLIC_IP = os.environ.get('WG_HOST', '152.92.137.58')
LAN_NETWORK = os.environ.get('LAN_NETWORK', '192.168.1.0/24')

# ---------------------------------------------------------------------------
# MikroTik (o WireGuard corre no router, não localmente)
# ---------------------------------------------------------------------------

import paramiko

WG_IFACE = 'wg0'
MIKROTIK_HOST = os.environ.get('MIKROTIK_HOST', '192.168.1.1')
MIKROTIK_PORT = int(os.environ.get('MIKROTIK_SSH_PORT', '22'))
MIKROTIK_USER = os.environ.get('MIKROTIK_USER', 'brmx')
MIKROTIK_PASS = os.environ.get('MIKROTIK_PASS', '')

_ROS_DURATION_RE = re.compile(
    r'^(?:(\d+)d)?(\d{1,3}):(\d{2}):(\d{2})$'
)


def _ros_escape(s):
    """Escapa uma string para uso seguro dentro de um script RouterOS entre aspas."""
    s = str(s or '')
    s = s.replace('\\', '\\\\').replace('"', '\\"')
    s = s.replace('\r', ' ').replace('\n', ' ').replace('$', '')
    return s


def mikrotik_run(script, timeout=15):
    """Executa um script RouterOS via SSH e devolve o stdout (texto)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(MIKROTIK_HOST, port=MIKROTIK_PORT, username=MIKROTIK_USER,
                        password=MIKROTIK_PASS, timeout=8, look_for_keys=False,
                        allow_agent=False)
        _, stdout, _ = client.exec_command(script, timeout=timeout)
        return stdout.read().decode('utf-8', 'replace')
    finally:
        client.close()


def parse_ros_duration(s):
    """Converte '[Xd]HH:MM:SS' (formato RouterOS) em segundos. Vazio -> 0."""
    s = (s or '').strip()
    if not s:
        return 0
    m = _ROS_DURATION_RE.match(s)
    if not m:
        return 0
    d, h, mi, se = (int(g) if g else 0 for g in m.groups())
    return d * 86400 + h * 3600 + mi * 60 + se


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS peers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            private_key TEXT NOT NULL,
            public_key TEXT NOT NULL,
            preshared_key TEXT NOT NULL,
            ip_address TEXT UNIQUE NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS peer_stats (
            peer_id INTEGER PRIMARY KEY,
            total_rx INTEGER NOT NULL DEFAULT 0,
            total_tx INTEGER NOT NULL DEFAULT 0,
            session_rx INTEGER NOT NULL DEFAULT 0,
            session_tx INTEGER NOT NULL DEFAULT 0,
            last_handshake INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (peer_id) REFERENCES peers(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS wol_machines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            mac TEXT UNIQUE NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            admin TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS traffic_daily (
            peer_id INTEGER NOT NULL,
            day TEXT NOT NULL,
            rx INTEGER NOT NULL DEFAULT 0,
            tx INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (peer_id, day)
        );
    ''')
    conn.commit()
    conn.close()


def migrate_db():
    """Adiciona colunas novas a bases de dados já existentes (idempotente)."""
    conn = get_db()
    cols_peers = {r['name'] for r in conn.execute('PRAGMA table_info(peers)')}
    if 'expires_at' not in cols_peers:
        conn.execute("ALTER TABLE peers ADD COLUMN expires_at TEXT")
    if 'full_tunnel' not in cols_peers:
        conn.execute("ALTER TABLE peers ADD COLUMN full_tunnel INTEGER NOT NULL DEFAULT 1")
    cols_stats = {r['name'] for r in conn.execute('PRAGMA table_info(peer_stats)')}
    if 'was_online' not in cols_stats:
        conn.execute("ALTER TABLE peer_stats ADD COLUMN was_online INTEGER NOT NULL DEFAULT 0")
    conn.commit()
    conn.close()


def log_action(action, details=''):
    conn = get_db()
    conn.execute(
        'INSERT INTO audit_log (ts, admin, action, details) VALUES (?, ?, ?, ?)',
        (datetime.now().isoformat(timespec='seconds'), session.get('user', '?'), action, details)
    )
    conn.commit()
    conn.close()


def send_telegram(text):
    """Envia notificação por Telegram (silencioso se não configurado)."""
    token = os.environ.get('TELEGRAM_TOKEN', '')
    chat_id = os.environ.get('TELEGRAM_CHAT_ID', '')
    if not token or not chat_id:
        return
    try:
        import urllib.request
        import urllib.parse
        url = f'https://api.telegram.org/bot{token}/sendMessage'
        data = urllib.parse.urlencode({'chat_id': chat_id, 'text': text}).encode()
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=5)
    except Exception:
        pass


def check_expirations():
    """Desativa peers cuja data de expiração já passou."""
    today = datetime.now().date().isoformat()
    conn = get_db()
    expired = conn.execute(
        'SELECT * FROM peers WHERE enabled=1 AND expires_at IS NOT NULL AND expires_at != "" AND expires_at < ?',
        (today,)
    ).fetchall()
    conn.close()
    if not expired:
        return
    iface = detect_interface()
    for peer in expired:
        peer = dict(peer)
        conn = get_db()
        conn.execute('UPDATE peers SET enabled=0 WHERE id=?', (peer['id'],))
        conn.commit()
        conn.close()
        wg_set_peer_enabled(iface, peer, False)
        log_action('expirar', f'"{peer["name"]}" desativado automaticamente (expirou em {peer["expires_at"]})')


# ---------------------------------------------------------------------------
# WireGuard helpers
# ---------------------------------------------------------------------------

def detect_interface():
    return WG_IFACE


def parse_server_config(iface):
    cfg = {'private_key': '', 'public_key': '', 'address': '10.8.0.1/24',
           'listen_port': 51820}
    # Nota: no RouterOS, via SSH não-interativo, cada linha corre como um
    # script à parte — variáveis :local não sobrevivem entre linhas, por
    # isso tem de ir tudo junto numa única linha (ou dentro de um bloco {}).
    script = (
        f':local pub [/interface wireguard get [find name="{iface}"] public-key]; '
        f':local lp [/interface wireguard get [find name="{iface}"] listen-port]; '
        f':local addr [/ip address get [find interface="{iface}"] address]; '
        f':put ($pub . "|" . $lp . "|" . $addr)\n'
    )
    try:
        out = mikrotik_run(script).strip()
        parts = out.split('|')
        if len(parts) >= 3 and parts[0]:
            cfg['public_key'] = parts[0].strip()
            cfg['listen_port'] = int(parts[1].strip())
            cfg['address'] = parts[2].strip()
    except Exception:
        pass
    return cfg


def generate_keypair():
    priv = subprocess.run(['wg', 'genkey'], capture_output=True, text=True).stdout.strip()
    pub = subprocess.run(['wg', 'pubkey'], input=priv,
                         capture_output=True, text=True).stdout.strip()
    psk = subprocess.run(['wg', 'genpsk'], capture_output=True, text=True).stdout.strip()
    return priv, pub, psk


def next_available_ip(iface):
    cfg = parse_server_config(iface)
    network = ipaddress.ip_interface(cfg['address']).network
    server_ip = str(ipaddress.ip_interface(cfg['address']).ip)

    conn = get_db()
    used = {row['ip_address'] for row in conn.execute('SELECT ip_address FROM peers')}
    conn.close()

    for host in network.hosts():
        ip = str(host)
        if ip != server_ip and ip not in used:
            return ip
    return None


def build_client_config(peer, iface):
    cfg = parse_server_config(iface)
    network = ipaddress.ip_interface(cfg['address']).network
    prefix = network.prefixlen
    if peer.get('full_tunnel', 1):
        allowed = '0.0.0.0/0, ::/0'
    else:
        # Split-tunnel: só a rede local (LAN + VPN), sem encaminhar a internet pelo servidor.
        allowed = f'{LAN_NETWORK}, {network}'
    return (
        f"[Interface]\n"
        f"PrivateKey = {peer['private_key']}\n"
        f"Address = {peer['ip_address']}/{prefix}\n"
        f"DNS = 1.1.1.1\n\n"
        f"[Peer]\n"
        f"PublicKey = {cfg['public_key']}\n"
        f"PresharedKey = {peer['preshared_key']}\n"
        f"Endpoint = {PUBLIC_IP}:{cfg['listen_port']}\n"
        f"AllowedIPs = {allowed}\n"
        f"PersistentKeepalive = 25\n"
    )


def wg_add_peer(iface, peer):
    name = _ros_escape(peer.get('name', ''))
    pub = _ros_escape(peer['public_key'])
    psk = _ros_escape(peer['preshared_key'])
    ip = _ros_escape(peer['ip_address'])
    script = (
        f'/interface wireguard peers add interface={iface} '
        f'public-key="{pub}" preshared-key="{psk}" '
        f'allowed-address="{ip}/32" persistent-keepalive=25s comment="{name}"\n'
    )
    mikrotik_run(script)


def wg_peer_exists(public_key):
    pub = _ros_escape(public_key)
    out = mikrotik_run(
        f':put ([:len [/interface wireguard peers find where public-key="{pub}"]] > 0)\n'
    ).strip()
    return out == 'true'


def wg_rename_peer(iface, public_key, name):
    pub = _ros_escape(public_key)
    nm = _ros_escape(name)
    mikrotik_run(f'/interface wireguard peers set [find public-key="{pub}"] comment="{nm}"\n')


def wg_remove_peer(iface, public_key):
    pub = _ros_escape(public_key)
    mikrotik_run(f'/interface wireguard peers remove [find public-key="{pub}"]\n')


def wg_set_peer_enabled(iface, peer, enabled):
    """Ativa/desativa um peer no Mikrotik (disabled=yes/no). Cria-o se não existir."""
    if enabled and not wg_peer_exists(peer['public_key']):
        wg_add_peer(iface, peer)
        return
    pub = _ros_escape(peer['public_key'])
    val = 'no' if enabled else 'yes'
    mikrotik_run(f'/interface wireguard peers set [find public-key="{pub}"] disabled={val}\n')


def _persist_config(iface):
    # RouterOS guarda a própria configuração automaticamente; nada a fazer.
    pass


def wg_stats(iface):
    """Retorna dict public_key -> {rx, tx, last_handshake, endpoint} da sessão actual."""
    # Nota: tem de ir tudo numa única linha — o SSH não-interativo do
    # RouterOS trata cada '\n' como um script novo e independente, mesmo
    # a meio de um bloco {} (a chave não "segura" entre linhas).
    script = (
        f':foreach i in=[/interface wireguard peers find where interface="{iface}"] do={{'
        f':local pk [/interface wireguard peers get $i public-key]; '
        f':local rx [/interface wireguard peers get $i rx]; '
        f':local tx [/interface wireguard peers get $i tx]; '
        f':local lh [/interface wireguard peers get $i last-handshake]; '
        f':local ep [/interface wireguard peers get $i current-endpoint-address]; '
        f':local epp [/interface wireguard peers get $i current-endpoint-port]; '
        f':put ($pk . "|" . $rx . "|" . $tx . "|" . $lh . "|" . $ep . "|" . $epp)'
        f'}}\n'
    )
    stats = {}
    try:
        out = mikrotik_run(script)
        for line in out.splitlines():
            line = line.strip()
            if not line or '|' not in line:
                continue
            parts = line.split('|')
            if len(parts) < 6:
                continue
            pub_key, rx, tx, lh, ep, epp = parts[:6]
            if not pub_key:
                continue
            endpoint = f'{ep}:{epp}' if ep else None
            age = parse_ros_duration(lh)
            last_hs = int(time.time()) - age if lh else 0
            stats[pub_key] = {
                'rx': int(rx) if rx.isdigit() else 0,
                'tx': int(tx) if tx.isdigit() else 0,
                'last_handshake': last_hs,
                'endpoint': endpoint,
            }
    except Exception:
        pass
    return stats


def wg_status(iface):
    now = time.time()
    return {k for k, v in wg_stats(iface).items()
            if v['last_handshake'] > 0 and (now - v['last_handshake']) < 180}


def update_peer_stats(iface):
    """Lê contadores do wg e acumula na BD (detecta resets por reinício do serviço)."""
    live = wg_stats(iface)
    if not live:
        return
    conn = get_db()
    peers = conn.execute('SELECT id, name, public_key FROM peers').fetchall()
    now_str = datetime.now().isoformat(timespec='seconds')
    today = datetime.now().date().isoformat()
    now = time.time()
    for peer in peers:
        s = live.get(peer['public_key'])
        if not s:
            continue
        is_online = s['last_handshake'] > 0 and (now - s['last_handshake']) < 180
        row = conn.execute('SELECT * FROM peer_stats WHERE peer_id=?', (peer['id'],)).fetchone()
        if row:
            # Detectar reset: se live < sessão anterior, o serviço reiniciou
            prev_rx = row['session_rx']
            prev_tx = row['session_tx']
            if s['rx'] < prev_rx or s['tx'] < prev_tx:
                # Reinício — guarda o que havia e começa nova sessão
                new_total_rx = row['total_rx'] + prev_rx
                new_total_tx = row['total_tx'] + prev_tx
            else:
                new_total_rx = row['total_rx']
                new_total_tx = row['total_tx']
            if is_online and not row['was_online']:
                send_telegram(f'🔌 "{peer["name"]}" ligou-se à VPN.')
            conn.execute(
                'UPDATE peer_stats SET total_rx=?, total_tx=?, session_rx=?, session_tx=?, '
                'last_handshake=?, updated_at=?, was_online=? WHERE peer_id=?',
                (new_total_rx, new_total_tx, s['rx'], s['tx'],
                 s['last_handshake'], now_str, int(is_online), peer['id'])
            )
            conn.execute(
                'INSERT INTO traffic_daily (peer_id, day, rx, tx) VALUES (?, ?, ?, ?) '
                'ON CONFLICT(peer_id, day) DO UPDATE SET rx=excluded.rx, tx=excluded.tx',
                (peer['id'], today, new_total_rx + s['rx'], new_total_tx + s['tx'])
            )
        else:
            if is_online:
                send_telegram(f'🔌 "{peer["name"]}" ligou-se à VPN.')
            conn.execute(
                'INSERT INTO peer_stats (peer_id, total_rx, total_tx, session_rx, session_tx, '
                'last_handshake, updated_at, was_online) VALUES (?, 0, 0, ?, ?, ?, ?, ?)',
                (peer['id'], s['rx'], s['tx'], s['last_handshake'], now_str, int(is_online))
            )
    conn.commit()
    conn.close()


def import_peers_from_conf(iface):
    """Sincroniza para a BD local os peers que já existem no Mikrotik
    (ex.: criados diretamente no Winbox) mas ainda não estão aqui."""
    script = (
        f':foreach i in=[/interface wireguard peers find where interface="{iface}"] do={{'
        f':local pk [/interface wireguard peers get $i public-key]; '
        f':local psk [/interface wireguard peers get $i preshared-key]; '
        f':local aa [/interface wireguard peers get $i allowed-address]; '
        f':local cm [/interface wireguard peers get $i comment]; '
        f':put ($pk . "|" . $psk . "|" . $aa . "|" . $cm)'
        f'}}\n'
    )
    try:
        out = mikrotik_run(script)
    except Exception as exc:
        return 0, f'Erro a ligar ao Mikrotik: {exc}'

    conn = get_db()
    imported = 0
    idx = 0
    for line in out.splitlines():
        line = line.strip()
        if not line or '|' not in line:
            continue
        idx += 1
        parts = line.split('|', 3)
        if len(parts) < 3:
            continue
        pub_key = parts[0]
        psk = parts[1]
        allowed = parts[2]
        comment = parts[3] if len(parts) > 3 else ''
        if not pub_key or not allowed:
            continue
        try:
            ip = str(ipaddress.ip_interface(allowed.split(',')[0].strip()).ip)
        except ValueError:
            continue
        if conn.execute('SELECT 1 FROM peers WHERE public_key=?', (pub_key,)).fetchone():
            continue
        name = comment or f'peer-{idx}'
        base, n = name, 1
        while conn.execute('SELECT 1 FROM peers WHERE name=?', (name,)).fetchone():
            name = f'{base}-{n}'
            n += 1
        try:
            conn.execute(
                'INSERT INTO peers (name, private_key, public_key, preshared_key, ip_address, enabled, created_at) '
                'VALUES (?, ?, ?, ?, ?, 1, ?)',
                (name, '', pub_key, psk, ip,
                 datetime.now().isoformat(timespec='seconds'))
            )
            imported += 1
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()
    return imported, None


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# CSRF (proteção simples baseada em token de sessão, sem dependências extra)
# ---------------------------------------------------------------------------

def get_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': get_csrf_token()}


@app.before_request
def check_csrf():
    if request.method == 'POST' and request.endpoint not in ('login', 'setup'):
        sent = request.form.get('csrf_token', '')
        expected = session.get('csrf_token', '')
        if not expected or not secrets.compare_digest(sent, expected):
            abort(403)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    conn = get_db()
    if conn.execute('SELECT COUNT(*) FROM admin').fetchone()[0] > 0:
        conn.close()
        return redirect(url_for('login'))
    conn.close()

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Preenche todos os campos.')
            return render_template('setup.html')
        conn = get_db()
        conn.execute('INSERT INTO admin (username, password_hash) VALUES (?, ?)',
                     (username, generate_password_hash(password)))
        conn.commit()
        conn.close()
        flash('Conta criada. Faz login.')
        return redirect(url_for('login'))
    return render_template('setup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    conn = get_db()
    if conn.execute('SELECT COUNT(*) FROM admin').fetchone()[0] == 0:
        conn.close()
        return redirect(url_for('setup'))
    conn.close()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        row = conn.execute('SELECT * FROM admin WHERE username=?', (username,)).fetchone()
        conn.close()
        if row and check_password_hash(row['password_hash'], password):
            session['user'] = username
            log_action('login', 'sessão iniciada')
            return redirect(url_for('dashboard'))
        flash('Credenciais inválidas.')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def dashboard():
    iface = detect_interface()
    check_expirations()
    update_peer_stats(iface)
    active_keys = wg_status(iface)
    conn = get_db()
    peers = conn.execute('SELECT * FROM peers ORDER BY created_at DESC').fetchall()
    conn.close()
    peers = [dict(p) for p in peers]
    today = datetime.now().date().isoformat()
    for p in peers:
        p['online'] = p['public_key'] in active_keys
        p['expired'] = bool(p['expires_at']) and p['expires_at'] < today
    server = parse_server_config(iface)
    return render_template('dashboard.html', peers=peers, iface=iface,
                           server=server, public_ip=PUBLIC_IP)


def peer_daily_history(peer_id, days=14):
    """Devolve lista de (dia, bytes_do_dia) para os últimos N dias, a partir dos
    snapshots acumulados em traffic_daily (delta entre dias consecutivos)."""
    conn = get_db()
    rows = conn.execute(
        'SELECT day, rx, tx FROM traffic_daily WHERE peer_id=? ORDER BY day', (peer_id,)
    ).fetchall()
    conn.close()
    history = []
    prev = None
    for r in rows:
        total = r['rx'] + r['tx']
        delta = max(0, total - prev) if prev is not None else 0
        history.append({'day': r['day'], 'bytes': delta})
        prev = total
    return history[-days:]


@app.route('/stats')
@login_required
def stats_page():
    iface = detect_interface()
    update_peer_stats(iface)
    live = wg_stats(iface)
    conn = get_db()
    peers = conn.execute('SELECT * FROM peers ORDER BY name').fetchall()
    rows = conn.execute('SELECT * FROM peer_stats').fetchall()
    conn.close()

    stats_by_peer = {r['peer_id']: dict(r) for r in rows}
    peers = [dict(p) for p in peers]
    now = time.time()
    for p in peers:
        s = stats_by_peer.get(p['id'], {})
        lv = live.get(p['public_key'], {})
        total_rx = s.get('total_rx', 0) + s.get('session_rx', 0)
        total_tx = s.get('total_tx', 0) + s.get('session_tx', 0)
        last_hs = s.get('last_handshake', 0)
        p['total_rx'] = total_rx
        p['total_tx'] = total_tx
        p['last_handshake'] = last_hs
        p['endpoint'] = lv.get('endpoint')
        p['online'] = last_hs > 0 and (now - last_hs) < 180
        history = peer_daily_history(p['id'])
        p['history_max'] = max([h['bytes'] for h in history], default=0) or 1
        p['history'] = history

    return render_template('stats.html', peers=peers, iface=iface, public_ip=PUBLIC_IP)


@app.route('/api/stats')
@login_required
def api_stats():
    iface = detect_interface()
    update_peer_stats(iface)
    live = wg_stats(iface)
    conn = get_db()
    peers = conn.execute('SELECT id, public_key FROM peers').fetchall()
    rows = conn.execute('SELECT * FROM peer_stats').fetchall()
    conn.close()
    stats_by_peer = {r['peer_id']: dict(r) for r in rows}
    now = time.time()
    result = {}
    for peer in peers:
        s = stats_by_peer.get(peer['id'], {})
        lv = live.get(peer['public_key'], {})
        last_hs = s.get('last_handshake', 0)
        result[peer['id']] = {
            'rx': s.get('total_rx', 0) + s.get('session_rx', 0),
            'tx': s.get('total_tx', 0) + s.get('session_tx', 0),
            'last_handshake': last_hs,
            'online': last_hs > 0 and (now - last_hs) < 180,
            'endpoint': lv.get('endpoint'),
        }
    return jsonify(result)


@app.route('/peer/add', methods=['POST'])
@login_required
def add_peer():
    name = request.form['name'].strip()
    if not name:
        flash('Nome obrigatório.')
        return redirect(url_for('dashboard'))
    expires_at = request.form.get('expires_at', '').strip()
    full_tunnel = 1 if request.form.get('full_tunnel', '1') == '1' else 0

    iface = detect_interface()
    ip = next_available_ip(iface)
    if not ip:
        flash('Sem IPs disponíveis na subnet.')
        return redirect(url_for('dashboard'))

    priv, pub, psk = generate_keypair()
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO peers (name, private_key, public_key, preshared_key, ip_address, enabled, '
            'created_at, expires_at, full_tunnel) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)',
            (name, priv, pub, psk, ip, datetime.now().isoformat(timespec='seconds'),
             expires_at or None, full_tunnel)
        )
        conn.commit()
        peer = dict(conn.execute('SELECT * FROM peers WHERE public_key=?', (pub,)).fetchone())
        wg_add_peer(iface, peer)
        log_action('criar_peer', f'"{name}" ({ip})')
        flash(f'Utilizador "{name}" criado com IP {ip}.')
    except sqlite3.IntegrityError:
        flash(f'Já existe um utilizador com o nome "{name}".')
    finally:
        conn.close()
    return redirect(url_for('dashboard'))


@app.route('/peer/<int:peer_id>/toggle', methods=['POST'])
@login_required
def toggle_peer(peer_id):
    iface = detect_interface()
    conn = get_db()
    peer = conn.execute('SELECT * FROM peers WHERE id=?', (peer_id,)).fetchone()
    if not peer:
        abort(404)
    peer = dict(peer)
    new_state = 0 if peer['enabled'] else 1
    conn.execute('UPDATE peers SET enabled=? WHERE id=?', (new_state, peer_id))
    conn.commit()
    conn.close()

    wg_set_peer_enabled(iface, peer, bool(new_state))
    log_action('ativar' if new_state else 'desativar', f'"{peer["name"]}"')
    flash(f'"{peer["name"]}" {"ativado" if new_state else "desativado"}.')
    return redirect(url_for('dashboard'))


@app.route('/peer/<int:peer_id>/delete', methods=['POST'])
@login_required
def delete_peer(peer_id):
    iface = detect_interface()
    conn = get_db()
    peer = dict(conn.execute('SELECT * FROM peers WHERE id=?', (peer_id,)).fetchone())
    conn.execute('DELETE FROM peers WHERE id=?', (peer_id,))
    conn.commit()
    conn.close()
    wg_remove_peer(iface, peer['public_key'])
    log_action('eliminar_peer', f'"{peer["name"]}" ({peer["ip_address"]})')
    flash(f'"{peer["name"]}" eliminado.')
    return redirect(url_for('dashboard'))


@app.route('/peer/<int:peer_id>/rename', methods=['POST'])
@login_required
def rename_peer(peer_id):
    name = request.form.get('name', '').strip()
    if not name:
        flash('Nome não pode ser vazio.')
        return redirect(url_for('dashboard'))
    expires_at = request.form.get('expires_at', '').strip()
    full_tunnel = 1 if request.form.get('full_tunnel', '1') == '1' else 0
    iface = detect_interface()
    conn = get_db()
    try:
        peer = conn.execute('SELECT public_key FROM peers WHERE id=?', (peer_id,)).fetchone()
        conn.execute('UPDATE peers SET name=?, expires_at=?, full_tunnel=? WHERE id=?',
                     (name, expires_at or None, full_tunnel, peer_id))
        conn.commit()
        if peer:
            wg_rename_peer(iface, peer['public_key'], name)
        log_action('editar_peer', f'"{name}"')
    except sqlite3.IntegrityError:
        flash(f'Já existe um peer com o nome "{name}".')
    finally:
        conn.close()
    return redirect(url_for('dashboard'))


@app.route('/import', methods=['POST'])
@login_required
def import_peers():
    iface = detect_interface()
    count, err = import_peers_from_conf(iface)
    if err:
        flash(f'Erro ao importar: {err}')
    elif count == 0:
        flash('Nenhum peer novo para importar (já existem todos ou nenhum encontrado).')
    else:
        log_action('sincronizar', f'{count} peer(s) importados do Mikrotik')
        flash(f'{count} peer(s) importado(s) do Mikrotik.')
    return redirect(url_for('dashboard'))


@app.route('/export')
@login_required
def export_peers():
    import zipfile
    iface = detect_interface()
    conn = get_db()
    peers = conn.execute('SELECT * FROM peers WHERE private_key != ""').fetchall()
    conn.close()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for p in peers:
            config_text = build_client_config(dict(p), iface)
            zf.writestr(f"{p['name'].replace(' ', '_')}.conf", config_text)
    buf.seek(0)
    log_action('exportar', f'{len(peers)} peer(s)')
    filename = f"wg-peers-backup-{datetime.now().strftime('%Y%m%d')}.zip"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype='application/zip')


@app.route('/peer/<int:peer_id>/qr')
@login_required
def peer_qr(peer_id):
    iface = detect_interface()
    conn = get_db()
    peer = conn.execute('SELECT * FROM peers WHERE id=?', (peer_id,)).fetchone()
    conn.close()
    if not peer:
        abort(404)
    peer = dict(peer)
    if not peer['private_key']:
        flash('Este peer foi importado — chave privada não disponível no servidor. Usa a config original do dispositivo.')
        return redirect(url_for('dashboard'))
    config_text = build_client_config(peer, iface)
    img = qrcode.make(config_text)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode()
    return render_template('qr.html', peer=peer, qr_b64=b64,
                           config_text=config_text)


@app.route('/peer/<int:peer_id>/qr/download')
@login_required
def download_qr(peer_id):
    iface = detect_interface()
    conn = get_db()
    peer = conn.execute('SELECT * FROM peers WHERE id=?', (peer_id,)).fetchone()
    conn.close()
    if not peer:
        abort(404)
    peer = dict(peer)
    if not peer['private_key']:
        flash('Peer importado — chave privada não disponível.')
        return redirect(url_for('dashboard'))
    config_text = build_client_config(peer, iface)
    img = qrcode.make(config_text)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    filename = f"{peer['name'].replace(' ', '_')}_qr.png"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype='image/png')


@app.route('/peer/<int:peer_id>/download')
@login_required
def download_config(peer_id):
    iface = detect_interface()
    conn = get_db()
    peer = conn.execute('SELECT * FROM peers WHERE id=?', (peer_id,)).fetchone()
    conn.close()
    if not peer:
        abort(404)
    peer = dict(peer)
    if not peer['private_key']:
        flash('Peer importado — chave privada não disponível.')
        return redirect(url_for('dashboard'))
    config_text = build_client_config(peer, iface)
    buf = io.BytesIO(config_text.encode())
    filename = f"{peer['name'].replace(' ', '_')}.conf"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype='text/plain')


@app.route('/homelab')
@login_required
def homelab_page():
    return render_template('homelab.html')


@app.route('/help')
@login_required
def help_page():
    iface = detect_interface()
    server = parse_server_config(iface)
    return render_template('help.html', public_ip=PUBLIC_IP,
                           wg_port=server['listen_port'])


# ---------------------------------------------------------------------------
# Administradores
# ---------------------------------------------------------------------------

@app.route('/admins')
@login_required
def admins_page():
    conn = get_db()
    admins = conn.execute('SELECT id, username FROM admin ORDER BY username').fetchall()
    conn.close()
    return render_template('admins.html', admins=admins)


@app.route('/admins/add', methods=['POST'])
@login_required
def admins_add():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    if not username or not password:
        flash('Utilizador e password são obrigatórios.')
        return redirect(url_for('admins_page'))
    conn = get_db()
    try:
        conn.execute('INSERT INTO admin (username, password_hash) VALUES (?, ?)',
                     (username, generate_password_hash(password)))
        conn.commit()
        log_action('criar_admin', f'"{username}"')
        flash(f'Administrador "{username}" criado.')
    except sqlite3.IntegrityError:
        flash(f'Já existe um administrador "{username}".')
    finally:
        conn.close()
    return redirect(url_for('admins_page'))


@app.route('/admins/<int:admin_id>/delete', methods=['POST'])
@login_required
def admins_delete(admin_id):
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) FROM admin').fetchone()[0]
    target = conn.execute('SELECT username FROM admin WHERE id=?', (admin_id,)).fetchone()
    if not target:
        conn.close()
        abort(404)
    if total <= 1:
        conn.close()
        flash('Não podes eliminar o último administrador.')
        return redirect(url_for('admins_page'))
    if target['username'] == session.get('user'):
        conn.close()
        flash('Não podes eliminar a tua própria conta enquanto tens sessão iniciada.')
        return redirect(url_for('admins_page'))
    conn.execute('DELETE FROM admin WHERE id=?', (admin_id,))
    conn.commit()
    conn.close()
    log_action('eliminar_admin', f'"{target["username"]}"')
    flash(f'Administrador "{target["username"]}" eliminado.')
    return redirect(url_for('admins_page'))


# ---------------------------------------------------------------------------
# Auditoria
# ---------------------------------------------------------------------------

@app.route('/audit')
@login_required
def audit_page():
    conn = get_db()
    entries = conn.execute('SELECT * FROM audit_log ORDER BY id DESC LIMIT 300').fetchall()
    conn.close()
    return render_template('audit.html', entries=entries)


# ---------------------------------------------------------------------------
# System Monitor
# ---------------------------------------------------------------------------

_cpu_last = {'total': 0, 'idle': 0}


def _read_cpu_fields():
    with open('/proc/stat') as f:
        fields = list(map(int, f.readline().split()[1:]))
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
    return sum(fields), idle


def get_cpu_pct():
    total, idle = _read_cpu_fields()
    diff_total = total - _cpu_last['total']
    diff_idle  = idle  - _cpu_last['idle']
    _cpu_last['total'] = total
    _cpu_last['idle']  = idle
    if diff_total <= 0:
        return 0.0
    return round((1 - diff_idle / diff_total) * 100, 1)


def get_sysinfo():
    d = {'cpu_pct': get_cpu_pct()}

    mem = {}
    with open('/proc/meminfo') as f:
        for line in f:
            if ':' in line:
                k, v = line.split(':', 1)
                mem[k.strip()] = int(v.split()[0])
    total_kb = mem.get('MemTotal', 0)
    avail_kb = mem.get('MemAvailable', 0)
    d['ram_total'] = total_kb * 1024
    d['ram_used']  = (total_kb - avail_kb) * 1024
    d['ram_pct']   = round((total_kb - avail_kb) / total_kb * 100, 1) if total_kb else 0

    st = os.statvfs('/')
    disk_total = st.f_blocks * st.f_frsize
    disk_free  = st.f_bavail * st.f_frsize
    d['disk_total'] = disk_total
    d['disk_used']  = disk_total - disk_free
    d['disk_pct']   = round((disk_total - disk_free) / disk_total * 100, 1) if disk_total else 0

    try:
        with open('/sys/class/thermal/thermal_zone0/temp') as f:
            d['temp'] = round(int(f.read().strip()) / 1000, 1)
    except Exception:
        d['temp'] = None

    try:
        with open('/proc/uptime') as f:
            d['uptime'] = int(float(f.read().split()[0]))
    except Exception:
        d['uptime'] = 0

    nets = {}
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 10 and ':' in parts[0]:
                    iface = parts[0].rstrip(':')
                    nets[iface] = {'rx': int(parts[1]), 'tx': int(parts[9])}
    except Exception:
        pass
    d['net'] = nets

    return d


@app.route('/api/sysinfo')
@login_required
def api_sysinfo():
    return jsonify(get_sysinfo())


# ---------------------------------------------------------------------------
# Wake-on-LAN
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$')


def send_magic_packet(mac_str):
    mac = mac_str.replace(':', '').replace('-', '').upper()
    if len(mac) != 12:
        raise ValueError('MAC inválido')
    mac_bytes = bytes.fromhex(mac)
    magic = b'\xff' * 6 + mac_bytes * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(magic, ('255.255.255.255', 9))


@app.route('/wol')
@login_required
def wol_page():
    conn = get_db()
    machines = conn.execute('SELECT * FROM wol_machines ORDER BY name').fetchall()
    conn.close()
    return render_template('wol.html', machines=machines)


@app.route('/wol/add', methods=['POST'])
@login_required
def wol_add():
    name = request.form.get('name', '').strip()
    mac  = request.form.get('mac', '').strip()
    if not name or not _MAC_RE.match(mac):
        flash('Nome e MAC válido são obrigatórios (formato: AA:BB:CC:DD:EE:FF).')
        return redirect(url_for('wol_page'))
    conn = get_db()
    try:
        conn.execute('INSERT INTO wol_machines (name, mac) VALUES (?, ?)', (name, mac.upper()))
        conn.commit()
        log_action('wol_add', f'"{name}" ({mac.upper()})')
        flash(f'"{name}" adicionado.')
    except sqlite3.IntegrityError:
        flash(f'Já existe uma máquina com o MAC {mac}.')
    finally:
        conn.close()
    return redirect(url_for('wol_page'))


@app.route('/wol/send/<int:mid>', methods=['POST'])
@login_required
def wol_send(mid):
    conn = get_db()
    m = conn.execute('SELECT * FROM wol_machines WHERE id=?', (mid,)).fetchone()
    conn.close()
    if not m:
        abort(404)
    try:
        send_magic_packet(m['mac'])
        log_action('wol_send', f'"{m["name"]}" ({m["mac"]})')
        flash(f'Magic packet enviado para "{m["name"]}" ({m["mac"]}).')
    except Exception as exc:
        flash(f'Erro ao enviar: {exc}')
    return redirect(url_for('wol_page'))


@app.route('/wol/delete/<int:mid>', methods=['POST'])
@login_required
def wol_delete(mid):
    conn = get_db()
    m = conn.execute('SELECT name FROM wol_machines WHERE id=?', (mid,)).fetchone()
    if m:
        conn.execute('DELETE FROM wol_machines WHERE id=?', (mid,))
        conn.commit()
        log_action('wol_delete', f'"{m["name"]}"')
        flash(f'"{m["name"]}" removido.')
    conn.close()
    return redirect(url_for('wol_page'))


# ---------------------------------------------------------------------------
# Network Tools
# ---------------------------------------------------------------------------

_NET_TOOLS = {
    'ping':       lambda t, _: ['ping', '-c', '4', '-W', '2', t],
    'traceroute': lambda t, _: ['traceroute', '-n', '-m', '20', t],
    'dig':        lambda t, _: ['dig', '+noall', '+answer', t],
}

_TARGET_RE = re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')


@app.route('/network')
@login_required
def network_page():
    return render_template('network.html')


@app.route('/network/run')
@login_required
def network_run():
    tool = request.args.get('tool', '').strip()
    target = request.args.get('target', '').strip()
    port_arg = request.args.get('port', '').strip()

    def sse(lines):
        for line in lines:
            yield f'data: {line}\n\n'
        yield 'data: [FIM]\n\n'

    def err(msg):
        return Response(stream_with_context(sse([msg])),
                        mimetype='text/event-stream',
                        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

    if not _TARGET_RE.match(target):
        return err('Alvo inválido.')

    if tool == 'port':
        def port_check():
            try:
                p = int(port_arg)
                if not (1 <= p <= 65535):
                    raise ValueError
            except (ValueError, TypeError):
                yield 'Porta inválida (1–65535).'
                return
            try:
                with socket.create_connection((target, p), timeout=3):
                    yield f'Porta {p} em {target}: ABERTA'
            except ConnectionRefusedError:
                yield f'Porta {p} em {target}: FECHADA (connection refused)'
            except OSError as exc:
                yield f'Porta {p} em {target}: inacessível ({exc})'
        return Response(stream_with_context(sse(port_check())),
                        mimetype='text/event-stream',
                        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

    if tool not in _NET_TOOLS:
        return err('Ferramenta inválida.')

    cmd = _NET_TOOLS[tool](target, port_arg)

    def run_cmd():
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                yield line.rstrip()
            proc.wait()
        except FileNotFoundError:
            yield f"Comando '{cmd[0]}' não encontrado — instala com: sudo apt install {cmd[0]}"
        except Exception as exc:
            yield f'Erro: {exc}'

    return Response(stream_with_context(sse(run_cmd())),
                    mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


if __name__ == '__main__':
    init_db()
    migrate_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

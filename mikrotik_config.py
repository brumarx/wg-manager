"""Backups e configuração do MikroTik (RouterOS 7) por SSH.

As funções recebem `run`, que executa um script RouterOS e devolve o stdout
(no painel é `mikrotik_run`), para este módulo não depender do Flask.

Dois tipos de backup:
- binário (`/system backup save`), guardado na flash do router: é o único que
  repõe tudo (incluindo passwords e chaves) e restaura-se com um clique;
- export em texto (`/export`), guardado no Pi: legível, sobrevive a uma avaria
  do router, mas não inclui passwords.
"""

import ipaddress
import os
import re
from datetime import datetime

AUTO_PREFIX = 'wgm-auto-'
PRE_PREFIX = 'wgm-antes-'    # feito automaticamente antes de uma alteração pelo painel
MANUAL_PREFIX = 'wgm-'
ROUTER_DIR = 'flash/'        # na raiz os ficheiros ficam em RAM e perdem-se ao reiniciar
ROUTER_AUTO_KEEP = 5         # backups automáticos mantidos no router
LOCAL_AUTO_KEEP = 20         # exports automáticos mantidos no Pi

_BACKUP_NAME_RE = re.compile(r'^(flash/)?[A-Za-z0-9._-]{1,80}\.backup$')
_EXPORT_NAME_RE = re.compile(r'^router-\d{8}-\d{6}(-auto)?\.rsc$')
_ERROR_MARKERS = ('failure', 'error', 'expected', 'bad command', 'invalid',
                  'no such item', 'input does not match', 'not enough', 'already have')


class RouterError(Exception):
    """Erro com mensagem pronta a mostrar ao utilizador."""


def _stamp():
    return datetime.now().strftime('%Y%m%d-%H%M%S')


def write(run, *commands):
    """Executa comandos de escrita. O RouterOS não imprime nada quando correm
    bem; uma saída com marca de erro é tratada como falha."""
    out = run('\n'.join(commands) + '\n')
    if any(m in out.lower() for m in _ERROR_MARKERS):
        raise RouterError('O MikroTik recusou o comando: ' + ' '.join(out.split())[:300])
    return out


# ---------------------------------------------------------------------------
# Backups binários (no router)
# ---------------------------------------------------------------------------

def check_backup_name(name):
    if not _BACKUP_NAME_RE.match(name or ''):
        raise RouterError('Nome de backup inválido.')
    return name


def list_router_backups(run):
    out = run(':foreach i in=[/file find where type="backup"] do={:local r [/file get $i]; '
              ':put (($r->"name") . "|" . ($r->"size") . "|" . ($r->"last-modified"))}\n')
    rows = []
    for line in out.splitlines():
        parts = line.strip().split('|')
        if len(parts) != 3 or not parts[0].endswith('.backup'):
            continue
        name, size, modified = parts
        short = name.split('/')[-1]
        rows.append({
            'name': name,
            'short': short,
            'size': int(size) if size.isdigit() else 0,
            'modified': '' if modified.startswith('1970') else modified,
            'auto': short.startswith(AUTO_PREFIX),
            'pre': short.startswith(PRE_PREFIX),
            'panel': short.startswith(MANUAL_PREFIX),
        })
    rows.sort(key=lambda r: r['modified'], reverse=True)
    return rows


def create_router_backup(run, auto=False, pre=False):
    prefix = PRE_PREFIX if pre else AUTO_PREFIX if auto else MANUAL_PREFIX
    name = f'{ROUTER_DIR}{prefix}{_stamp()}'
    write(run, f'/system backup save name="{name}" dont-encrypt=yes')
    if auto or pre:
        kind = 'pre' if pre else 'auto'
        same = [b for b in list_router_backups(run) if b[kind]]
        for old in same[ROUTER_AUTO_KEEP:]:
            delete_router_backup(run, old['name'])
    return name + '.backup'


def _require_router_backup(run, name):
    check_backup_name(name)
    if not any(b['name'] == name for b in list_router_backups(run)):
        raise RouterError('Esse backup já não existe no router.')


def delete_router_backup(run, name):
    _require_router_backup(run, name)
    write(run, f'/file remove [find where name="{name}"]')


def restore_command(run, name):
    """Devolve o comando de restauro (o router reinicia logo a seguir).
    Tem de ser executado com confirmação ("y") — ver mikrotik_run_confirm."""
    _require_router_backup(run, name)
    return f'/system backup load name="{name}" password=""'


# ---------------------------------------------------------------------------
# Exports em texto (no Pi)
# ---------------------------------------------------------------------------

def check_export_name(name):
    if not _EXPORT_NAME_RE.match(name or ''):
        raise RouterError('Nome de ficheiro inválido.')
    return name


def create_export(run, directory, auto=False):
    out = run('/export\n', timeout=60)
    if '/system' not in out and '/interface' not in out:
        raise RouterError('O export veio vazio — o MikroTik não respondeu como esperado.')
    os.makedirs(directory, exist_ok=True)
    name = f'router-{_stamp()}{"-auto" if auto else ""}.rsc'
    with open(os.path.join(directory, name), 'w') as f:
        f.write(out.replace('\r\n', '\n'))
    if auto:
        autos = [e for e in list_exports(directory) if e['auto']]
        for old in autos[LOCAL_AUTO_KEEP:]:
            os.remove(os.path.join(directory, old['name']))
    return name


def list_exports(directory):
    if not os.path.isdir(directory):
        return []
    rows = []
    for name in os.listdir(directory):
        if not _EXPORT_NAME_RE.match(name):
            continue
        path = os.path.join(directory, name)
        rows.append({
            'name': name,
            'size': os.path.getsize(path),
            'modified': datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M:%S'),
            'auto': name.endswith('-auto.rsc'),
        })
    rows.sort(key=lambda r: r['name'][7:22], reverse=True)  # pela data no nome
    return rows


def export_path(directory, name):
    return os.path.join(directory, check_export_name(name))


def last_auto_time(directory):
    """Data do export automático mais recente (para o agendamento semanal)."""
    autos = [e for e in list_exports(directory) if e['auto']]
    if not autos:
        return None
    return datetime.strptime(autos[0]['name'][7:22], '%Y%m%d-%H%M%S')


# --- Configuração -----------------------------------------------------------

WGM = 'wgm:'                      # prefixo dos comentários criados pelo painel
BLOCK_LIST = 'wgm-bloqueados'     # address-list dos dispositivos bloqueados
BLOCK_RULE = 'wgm: bloquear dispositivos'
SCHED_PREFIX = 'wgm-horario:'     # comentário das regras de horário
SEP = '|'

LEASE_TIMES = ['10m', '30m', '1h', '12h', '1d', '3d']
DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']
DAY_NAMES = {'mon': 'Seg', 'tue': 'Ter', 'wed': 'Qua', 'thu': 'Qui',
             'fri': 'Sex', 'sat': 'Sáb', 'sun': 'Dom'}

_ID_RE = re.compile(r'^\*[0-9A-F]{1,8}$')
_MAC_RE = re.compile(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$')
_IDENTITY_RE = re.compile(r'^[A-Za-z0-9._-]{1,40}$')
_TEXT_RE = re.compile(r'^[\w À-ÿ.,:()+/#@&-]{0,60}$')
_TIME_RE = re.compile(r'^([01]\d|2[0-3]):([0-5]\d)$')
_PORTS_RE = re.compile(r'^\d{1,5}(-\d{1,5})?$')


# ---------------------------------------------------------------------------
# Validação
# ---------------------------------------------------------------------------

def ros_str(s):
    s = str(s or '').replace('\\', '\\\\').replace('"', '\\"')
    return s.replace('\r', ' ').replace('\n', ' ').replace('$', '')


def check_id(rid):
    if not _ID_RE.match(rid or ''):
        raise RouterError('Identificador inválido.')
    return rid


def check_text(s, field='Texto'):
    s = (s or '').strip()
    if not _TEXT_RE.match(s):
        raise RouterError(f'{field}: usa só letras, números e . , : ( ) + / # @ & - (máx. 60).')
    return s


def check_mac(mac):
    mac = (mac or '').strip().upper().replace('-', ':')
    if not _MAC_RE.match(mac):
        raise RouterError('Endereço MAC inválido.')
    return mac


def check_lan_ip(ip, lan):
    try:
        addr = ipaddress.ip_address((ip or '').strip())
    except ValueError:
        raise RouterError(f'IP inválido: {ip}')
    net = ipaddress.ip_network(lan, strict=False)
    if addr not in net or addr in (net.network_address, net.broadcast_address):
        raise RouterError(f'O IP {addr} tem de estar dentro da rede {net}.')
    return str(addr)


def check_ports(p):
    p = (p or '').strip()
    if not _PORTS_RE.match(p):
        raise RouterError('Porta inválida (ex.: 8080 ou 6000-6010).')
    nums = [int(x) for x in p.split('-')]
    if not all(1 <= n <= 65535 for n in nums) or (len(nums) == 2 and nums[0] > nums[1]):
        raise RouterError('Porta fora do intervalo 1–65535.')
    return p


def check_time(t):
    t = (t or '').strip()
    if not _TIME_RE.match(t):
        raise RouterError('Hora inválida (usa HH:MM).')
    return t



def _rows(run, path, fields, where=''):
    """Lê todos os registos de `path` como lista de dicts (inclui '.id')."""
    find = f'[{path} find {where}]' if where else f'[{path} find]'
    parts = ' . "|" . '.join(f'($r->"{f}")' for f in fields)
    out = run(f':foreach i in={find} do={{:local r [{path} get $i]; '
              f':put ($i . "|" . {parts})}}\n')
    rows = []
    for line in out.splitlines():
        line = line.rstrip('\r')
        if not line.startswith('*'):
            continue
        vals = line.split(SEP, len(fields))
        if len(vals) < len(fields) + 1:
            continue
        row = {'.id': vals[0]}
        row.update(zip(fields, vals[1:]))
        rows.append(row)
    return rows


def _bool(v):
    return str(v).strip() == 'true'



# ---------------------------------------------------------------------------
# Sistema
# ---------------------------------------------------------------------------

_SYSTEM_FIELDS = {
    'identity':         '/system identity get name',
    'model':            '/system routerboard get model',
    'version':          '/system resource get version',
    'uptime':           '/system resource get uptime',
    'cpu_load':         '/system resource get cpu-load',
    'free_memory':      '/system resource get free-memory',
    'total_memory':     '/system resource get total-memory',
    'firmware':         '/system routerboard get current-firmware',
    'firmware_upgrade': '/system routerboard get upgrade-firmware',
    'timezone':         '/system clock get time-zone-name',
    'date':             '/system clock get date',
    'time':             '/system clock get time',
    'dns_servers':      '/ip dns get servers',
    'wifi_count':       ':len [/interface find where type~"wlan|wifi"]',
}


def get_system(run):
    # :tostr evita que um valor-lista (ex.: vários DNS) repita o "k=" em cada elemento
    script = '; '.join(f':put ("{k}=" . [:tostr [{cmd}]])' for k, cmd in _SYSTEM_FIELDS.items())
    d = {}
    for line in run(script + '\n').splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            d[k.strip()] = v.strip()
    d['dns_servers'] = [x for x in d.get('dns_servers', '').split(';') if x]
    d['has_wifi'] = d.get('wifi_count', '0') not in ('', '0')
    d['free_memory_mb'] = _mib(d.get('free_memory'))
    d['total_memory_mb'] = _mib(d.get('total_memory'))
    d['firmware_outdated'] = bool(d.get('firmware_upgrade')) and d.get('firmware') != d.get('firmware_upgrade')
    return d


def _mib(v):
    try:
        return round(int(v) / 1048576)
    except (TypeError, ValueError):
        return None


def set_identity(run, name):
    name = (name or '').strip()
    if not _IDENTITY_RE.match(name):
        raise RouterError('Nome inválido: usa letras, números, ponto, hífen ou _ (máx. 40).')
    write(run, f'/system identity set name="{name}"')


def set_timezone(run, tz, valid_zones):
    if tz not in valid_zones:
        raise RouterError('Fuso horário inválido.')
    write(run, f'/system clock set time-zone-autodetect=no time-zone-name="{ros_str(tz)}"')


def set_dns(run, servers):
    ips = []
    for s in servers:
        s = s.strip()
        if not s:
            continue
        try:
            ips.append(str(ipaddress.ip_address(s)))
        except ValueError:
            raise RouterError(f'Servidor DNS inválido: {s}')
    if not ips:
        raise RouterError('Indica pelo menos um servidor DNS.')
    write(run, f'/ip dns set servers={",".join(ips[:4])}')
    write(run, '/ip dns cache flush')


# ---------------------------------------------------------------------------
# Rede: DHCP
# ---------------------------------------------------------------------------

def get_dhcp(run):
    servers = _rows(run, '/ip dhcp-server', ['name', 'interface', 'address-pool', 'lease-time'])
    server = servers[0] if servers else {}
    pool = {}
    if server.get('address-pool'):
        pools = _rows(run, '/ip pool', ['name', 'ranges'],
                      f'where name="{ros_str(server["address-pool"])}"')
        pool = pools[0] if pools else {}
    nets = _rows(run, '/ip dhcp-server network', ['address', 'gateway', 'dns-server'])
    leases = _rows(run, '/ip dhcp-server lease',
                   ['address', 'mac-address', 'host-name', 'status', 'dynamic',
                    'disabled', 'comment', 'last-seen'])
    for l in leases:
        l['dynamic'] = _bool(l['dynamic'])
        l['disabled'] = _bool(l['disabled'])
        l['name'] = l['comment'] or l['host-name'] or ''
        try:
            l['_sort'] = int(ipaddress.ip_address(l['address']))
        except ValueError:
            l['_sort'] = 0
    leases.sort(key=lambda l: l['_sort'])
    return {'server': server, 'pool': pool, 'network': nets[0] if nets else {},
            'leases': leases}


_LEASE_TIME_ROS = {'00:10:00': '10m', '00:30:00': '30m', '01:00:00': '1h',
                   '12:00:00': '12h', '1d00:00:00': '1d', '3d00:00:00': '3d'}


def lease_time_label(ros_value):
    """Converte o formato do RouterOS (ex.: 00:30:00) para a opção do painel (30m)."""
    return _LEASE_TIME_ROS.get((ros_value or '').replace(' ', ''), '')


def set_lease_time(run, server_id, lease_time):
    if lease_time not in LEASE_TIMES:
        raise RouterError('Tempo de lease inválido.')
    write(run, f'/ip dhcp-server set {check_id(server_id)} lease-time={lease_time}')


def set_pool_range(run, pool_id, start, end, lan, gateway):
    a = ipaddress.IPv4Address(check_lan_ip(start, lan))
    b = ipaddress.IPv4Address(check_lan_ip(end, lan))
    if a > b:
        raise RouterError('O início do intervalo tem de ser menor que o fim.')
    gw = ipaddress.IPv4Address(gateway) if gateway else None
    if gw and a <= gw <= b:
        raise RouterError(f'O intervalo não pode incluir o IP do router ({gw}).')
    write(run, f'/ip pool set {check_id(pool_id)} ranges={a}-{b}')


def _lease(run, lease_id):
    rows = _rows(run, '/ip dhcp-server lease', ['address', 'mac-address', 'dynamic', 'comment'],
                 f'where .id={check_id(lease_id)}')
    if not rows:
        raise RouterError('Dispositivo não encontrado na lista do DHCP.')
    rows[0]['dynamic'] = _bool(rows[0]['dynamic'])
    return rows[0]


def make_static(run, lease_id):
    lease = _lease(run, lease_id)
    if lease['dynamic']:
        write(run, f'/ip dhcp-server lease make-static {lease_id}')
    return lease


def update_lease(run, lease_id, address, comment, lan, gateway):
    """Fixa o IP de um dispositivo (torna o lease estático) e dá-lhe um nome."""
    lease = make_static(run, lease_id)
    comment = check_text(comment, 'Nome')
    address = check_lan_ip(address, lan)
    if gateway and address == gateway:
        raise RouterError('Esse IP é o do próprio router.')
    if address != lease['address']:
        taken = run(f':put [:len [/ip dhcp-server lease find where address={address} '
                    f'and .id!={lease_id}]]\n').strip()
        if taken not in ('', '0'):
            raise RouterError(f'O IP {address} já está atribuído a outro dispositivo.')
    write(run, f'/ip dhcp-server lease set {lease_id} address={address} comment="{ros_str(comment)}"')


def add_static_lease(run, mac, address, comment, lan, gateway):
    mac = check_mac(mac)
    address = check_lan_ip(address, lan)
    comment = check_text(comment, 'Nome')
    if gateway and address == gateway:
        raise RouterError('Esse IP é o do próprio router.')
    existing = _rows(run, '/ip dhcp-server lease', ['address', 'mac-address'],
                     f'where mac-address="{mac}"')
    if existing:
        return update_lease(run, existing[0]['.id'], address, comment, lan, gateway)
    taken = run(f':put [:len [/ip dhcp-server lease find where address={address}]]\n').strip()
    if taken not in ('', '0'):
        raise RouterError(f'O IP {address} já está atribuído a outro dispositivo.')
    server = (_rows(run, '/ip dhcp-server', ['name']) or [{}])[0].get('name', '')
    write(run, f'/ip dhcp-server lease add mac-address={mac} address={address} '
               f'server="{ros_str(server)}" comment="{ros_str(comment)}"')


def remove_lease(run, lease_id):
    _lease(run, lease_id)
    write(run, f'/ip dhcp-server lease remove {lease_id}')


# ---------------------------------------------------------------------------
# Portas (dst-nat) e firewall
# ---------------------------------------------------------------------------

def get_wan(run):
    """IP da WAN e se é privado (ou seja, o router está atrás da box do ISP)."""
    ifaces = run(':foreach m in=[/interface list member find where list=WAN] do={'
                 ':put [/interface list member get $m interface]}\n').split()
    rows = [r for r in _rows(run, '/ip address', ['address', 'interface'])
            if r['interface'] in ifaces]
    if not rows:
        return {'address': '', 'private': False}
    addr = rows[0]['address'].split('/')[0]
    try:
        private = ipaddress.ip_address(addr).is_private
    except ValueError:
        private = False
    return {'address': addr, 'private': private}


def list_port_forwards(run):
    rows = _rows(run, '/ip firewall nat',
                 ['chain', 'action', 'protocol', 'dst-port', 'to-addresses', 'to-ports',
                  'disabled', 'comment', 'in-interface', 'in-interface-list'],
                 'where chain=dstnat')
    for r in rows:
        r['disabled'] = _bool(r['disabled'])
    return rows


def add_port_forward(run, name, protocol, ext_port, ip, int_port, lan):
    name = check_text(name, 'Nome')
    if protocol not in ('tcp', 'udp', 'both'):
        raise RouterError('Protocolo inválido.')
    ext_port = check_ports(ext_port)
    int_port = check_ports(int_port or ext_port)
    ip = check_lan_ip(ip, lan)
    for proto in (['tcp', 'udp'] if protocol == 'both' else [protocol]):
        comment = ros_str(f'{WGM} {name or "porta " + ext_port} ({proto.upper()})')
        write(run, f'/ip firewall nat add chain=dstnat action=dst-nat in-interface-list=WAN '
                   f'protocol={proto} dst-port={ext_port} to-addresses={ip} '
                   f'to-ports={int_port} comment="{comment}"')


def _check_nat(run, rule_id):
    rows = _rows(run, '/ip firewall nat', ['chain'], f'where .id={check_id(rule_id)}')
    if not rows or rows[0]['chain'] != 'dstnat':
        raise RouterError('Redirecionamento não encontrado.')


def set_port_forward_enabled(run, rule_id, enabled):
    _check_nat(run, rule_id)
    write(run, f'/ip firewall nat set {rule_id} disabled={"no" if enabled else "yes"}')


def remove_port_forward(run, rule_id):
    _check_nat(run, rule_id)
    write(run, f'/ip firewall nat remove {rule_id}')


def list_filter_rules(run):
    rows = _rows(run, '/ip firewall filter',
                 ['chain', 'action', 'protocol', 'dst-port', 'src-address', 'dst-address',
                  'in-interface', 'in-interface-list', 'src-address-list',
                  'connection-state', 'time', 'disabled', 'dynamic', 'comment', 'packets'])
    for r in rows:
        r['disabled'] = _bool(r['disabled'])
        r['dynamic'] = _bool(r['dynamic'])
        c = r['comment']
        r['locked'] = r['dynamic'] or c.startswith('defconf') or c.startswith(('wgm', 'wgm-'))
        bits = []
        for k, label in (('protocol', ''), ('dst-port', 'porta '), ('src-address', 'de '),
                         ('dst-address', 'para '), ('in-interface', 'entrada '),
                         ('in-interface-list', 'entrada '), ('src-address-list', 'lista '),
                         ('connection-state', ''), ('time', 'horário ')):
            if r.get(k):
                bits.append(label + r[k])
        r['summary'] = ' · '.join(bits)
    return rows


def set_filter_enabled(run, rule_id, enabled):
    rows = [r for r in list_filter_rules(run) if r['.id'] == check_id(rule_id)]
    if not rows:
        raise RouterError('Regra não encontrada.')
    if rows[0]['locked']:
        raise RouterError('Esta regra faz parte da configuração base e não pode ser alterada aqui.')
    write(run, f'/ip firewall filter set {rule_id} disabled={"no" if enabled else "yes"}')


# ---------------------------------------------------------------------------
# Controlo: bloquear dispositivos
# ---------------------------------------------------------------------------

def _first_forward_rule(run):
    return run(':put [:pick [/ip firewall filter find where chain=forward and dynamic=no] 0]\n').strip()


def _place_before(run):
    first = _first_forward_rule(run)
    return f' place-before={first}' if _ID_RE.match(first) else ''


def ensure_block_rule(run):
    """Garante a regra que corta a internet à address-list de bloqueados,
    antes do fasttrack (senão ligações já abertas continuavam a passar)."""
    n = run(f':put [:len [/ip firewall filter find where comment="{BLOCK_RULE}"]]\n').strip()
    if n in ('', '0'):
        write(run, f'/ip firewall filter add chain=forward action=drop '
                   f'src-address-list={BLOCK_LIST} comment="{BLOCK_RULE}"{_place_before(run)}')


def _kill_connections(ip):
    return f'/ip firewall connection remove [find where src-address~"^{ip}:"]'


def get_control(run):
    blocked = {r['address']: r for r in
               _rows(run, '/ip firewall address-list', ['list', 'address', 'comment'],
                     f'where list={BLOCK_LIST}')}
    sched_rules = _rows(run, '/ip firewall filter', ['src-address', 'time', 'comment', 'disabled'],
                        f'where comment~"^{SCHED_PREFIX}"')
    schedules = {}
    for r in sched_rules:
        # comentário: "wgm-horario: <MAC> HH:MM-HH:MM dias"
        parts = r['comment'][len(SCHED_PREFIX):].split()
        if len(parts) >= 3:
            schedules.setdefault(parts[0], {'mac': parts[0], 'window': parts[1],
                                            'days': parts[2].split(','), 'ip': r['src-address']})
    return {'blocked': blocked, 'schedules': schedules}


def block_device(run, lease_id):
    lease = make_static(run, lease_id)  # IP fixo para o bloqueio não falhar se o IP mudar
    ip, mac = lease['address'], lease['mac-address']
    ensure_block_rule(run)
    n = run(f':put [:len [/ip firewall address-list find where list={BLOCK_LIST} '
            f'and address={ip}]]\n').strip()
    if n in ('', '0'):
        write(run, f'/ip firewall address-list add list={BLOCK_LIST} address={ip} '
                   f'comment="{WGM} {mac}"')
    write(run, _kill_connections(ip))
    return lease


def unblock_device(run, lease_id):
    lease = _lease(run, lease_id)
    write(run, f'/ip firewall address-list remove [find where list={BLOCK_LIST} '
               f'and address={lease["address"]}]')
    return lease


def _shift_days(days):
    return [DAYS[(DAYS.index(d) + 1) % 7] for d in days]


def set_schedule(run, lease_id, start, end, days):
    """Corta a internet ao dispositivo todos os `days` entre `start` e `end`.
    Se o intervalo passa a meia-noite, cria duas regras (a 2.ª nos dias seguintes)."""
    start, end = check_time(start), check_time(end)
    days = [d for d in DAYS if d in (days or [])]
    if not days:
        raise RouterError('Escolhe pelo menos um dia.')
    if start == end:
        raise RouterError('A hora de início e de fim não podem ser iguais.')
    lease = make_static(run, lease_id)
    ip, mac = lease['address'], lease['mac-address'].upper()
    clear_schedule(run, lease_id)
    comment = f'{SCHED_PREFIX} {mac} {start}-{end} {",".join(days)}'
    if start < end:
        windows = [(start + ':00', end + ':00', days)]
    else:
        windows = [(start + ':00', '23:59:59', days), ('00:00:00', end + ':00', _shift_days(days))]
    place = _place_before(run)
    for a, b, ds in windows:
        write(run, f'/ip firewall filter add chain=forward action=drop src-address={ip} '
                   f'time={a}-{b},{",".join(ds)} comment="{comment}"{place}')
    # As ligações abertas antes do início continuariam (fasttrack); um agendamento
    # diário no router fecha-as à hora de início.
    sched = f'wgm-horario-{mac.replace(":", "")}'
    event = ros_str(_kill_connections(ip))
    write(run, f'/system scheduler add name="{sched}" start-time={start}:00 interval=1d '
               f'on-event="{event}" comment="{WGM} horário {mac}"')


def clear_schedule(run, lease_id):
    lease = _lease(run, lease_id)
    mac = lease['mac-address'].upper()
    write(run, f'/ip firewall filter remove [find where comment~"^{SCHED_PREFIX} {mac} "]')
    write(run, f'/system scheduler remove [find where name="wgm-horario-{mac.replace(":", "")}"]')
    return lease


"""Backups da configuração do MikroTik (RouterOS 7) por SSH.

As funções recebem `run`, que executa um script RouterOS e devolve o stdout
(no painel é `mikrotik_run`), para este módulo não depender do Flask.

Dois tipos de backup:
- binário (`/system backup save`), guardado na flash do router: é o único que
  repõe tudo (incluindo passwords e chaves) e restaura-se com um clique;
- export em texto (`/export`), guardado no Pi: legível, sobrevive a uma avaria
  do router, mas não inclui passwords.
"""

import os
import re
from datetime import datetime

AUTO_PREFIX = 'wgm-auto-'
MANUAL_PREFIX = 'wgm-'
ROUTER_DIR = 'flash/'        # na raiz os ficheiros ficam em RAM e perdem-se ao reiniciar
ROUTER_AUTO_KEEP = 5         # backups automáticos mantidos no router
LOCAL_AUTO_KEEP = 20         # exports automáticos mantidos no Pi

_BACKUP_NAME_RE = re.compile(r'^(flash/)?[A-Za-z0-9._-]{1,80}\.backup$')
_EXPORT_NAME_RE = re.compile(r'^router-\d{8}-\d{6}(-auto)?\.rsc$')
_ERROR_MARKERS = ('failure', 'error', 'expected', 'bad command', 'invalid',
                  'no such item', 'input does not match', 'not enough')


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
            'panel': short.startswith(MANUAL_PREFIX),
        })
    rows.sort(key=lambda r: r['modified'], reverse=True)
    return rows


def create_router_backup(run, auto=False):
    name = f'{ROUTER_DIR}{AUTO_PREFIX if auto else MANUAL_PREFIX}{_stamp()}'
    write(run, f'/system backup save name="{name}" dont-encrypt=yes')
    if auto:
        autos = [b for b in list_router_backups(run) if b['auto']]
        for old in autos[ROUTER_AUTO_KEEP:]:
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

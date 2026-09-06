#!/usr/bin/env python3
"""Renomeia peers na BD do wg-manager a partir de ficheiros .conf de clientes.
Uso: sudo python3 rename_from_confs.py /pasta/com/confs/
"""
import sys
import os
import glob
import sqlite3
import ipaddress

DB_PATH = '/opt/wg-manager/wg_manager.db'

def parse_conf(path):
    """Extrai IP e chave privada do [Interface] de um ficheiro cliente."""
    result = {'ip': None, 'private_key': None}
    in_interface = False
    with open(path) as f:
        for line in f:
            s = line.strip()
            if s == '[Interface]':
                in_interface = True
            elif s.startswith('['):
                in_interface = False
            elif in_interface and '=' in s:
                k, v = s.split('=', 1)
                k, v = k.strip(), v.strip()
                if k == 'Address':
                    try:
                        result['ip'] = str(ipaddress.ip_interface(v.split(',')[0]).ip)
                    except ValueError:
                        pass
                elif k == 'PrivateKey':
                    result['private_key'] = v
    return result

def main():
    conf_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    confs = sorted(glob.glob(os.path.join(conf_dir, '*.conf')))

    if not confs:
        print(f'Nenhum .conf encontrado em {conf_dir}')
        sys.exit(1)

    if not os.path.exists(DB_PATH):
        print(f'BD não encontrada: {DB_PATH}')
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    updated = skipped = 0

    for path in confs:
        filename = os.path.basename(path)
        name = os.path.splitext(filename)[0]
        data = parse_conf(path)

        if not data['ip']:
            print(f'  SKIP  {filename}: sem campo Address')
            skipped += 1
            continue

        row = conn.execute(
            'SELECT id, name FROM peers WHERE ip_address=?', (data['ip'],)
        ).fetchone()

        if not row:
            print(f'  SKIP  {filename}: IP {data["ip"]} não existe na BD')
            skipped += 1
            continue

        peer_id, old_name = row

        # Verificar conflito de nome com outro peer
        conflict = conn.execute(
            'SELECT id FROM peers WHERE name=? AND id!=?', (name, peer_id)
        ).fetchone()
        if conflict:
            print(f'  SKIP  {filename}: nome "{name}" já usado por outro peer')
            skipped += 1
            continue

        conn.execute('UPDATE peers SET name=? WHERE id=?', (name, peer_id))
        print(f'  OK    {old_name:20s} -> {name}  ({data["ip"]})')
        updated += 1

    conn.commit()
    conn.close()
    print(f'\nTotal: {updated} renomeado(s), {skipped} ignorado(s)')
    if updated:
        print('Recarrega a página do wg-manager para ver os nomes actualizados.')

if __name__ == '__main__':
    main()

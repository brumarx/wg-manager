# WireGuard Manager

Painel web para gerir os utilizadores (peers) de um servidor WireGuard que
corre num router **MikroTik (RouterOS 7+)**, em vez de correr localmente na
máquina onde o painel está instalado.

O painel comunica com o MikroTik por SSH (RouterOS scripting), por isso pode
correr em qualquer máquina Linux da tua rede (um Raspberry Pi, um servidor,
um container) — só precisa de alcançar o router por SSH.

![Python](https://img.shields.io/badge/python-3.10+-blue) ![Flask](https://img.shields.io/badge/flask-3.x-black) ![RouterOS](https://img.shields.io/badge/RouterOS-7%2B-informational)

## Porquê

As soluções típicas de gestão de WireGuard (wg-easy, wireguard-ui, etc.)
partem do princípio que o WireGuard corre na mesma máquina que a UI. Se o teu
WireGuard corre no router (mais estável, sobrevive a reboots do servidor,
não depende de um serviço Linux ficar de pé), essas ferramentas não servem.
Este painel resolve isso falando diretamente com o RouterOS por SSH.

## Funcionalidades

- **Gestão de utilizadores VPN** — criar, editar, ativar/desativar, eliminar;
  geração automática de chaves (privada, pública, preshared).
- **QR code e download de `.conf`** por utilizador, prontos a importar na app
  WireGuard (telemóvel ou desktop).
- **Dois modos de acesso por utilizador**: túnel total (internet + rede
  local) ou só rede local (não encaminha internet pelo servidor).
- **Expiração automática** — define uma data e o peer é desativado sozinho
  quando expira (acesso temporário/convidado).
- **Estatísticas em tempo real** — quem está online, tráfego, endpoint atual,
  e um pequeno histórico de uso dos últimos 14 dias por utilizador.
- **Notificações por Telegram** (opcional) quando um utilizador liga à VPN.
- **Exportação/backup** de todas as configurações num `.zip`.
- **Múltiplos administradores** com página de gestão de contas.
- **Registo de auditoria** — quem fez o quê e quando, neste painel.
- **Wake-on-LAN** — acordar máquinas da rede local por magic packet.
- **Ferramentas de rede** — ping, traceroute, DNS e verificação de porta,
  direto do painel.
- **Sincronização com o MikroTik** — importa peers criados diretamente no
  router (Winbox) para a base de dados do painel.
- Login com password, proteção CSRF em todas as ações, e monitor do sistema
  (CPU/RAM/disco/temperatura) da própria máquina onde o painel corre.

## Arquitetura

```
┌─────────────────┐        SSH (RouterOS API)        ┌──────────────────┐
│  WireGuard       │ ────────────────────────────────▶│     MikroTik     │
│  Manager (Flask) │                                   │  (WireGuard real  │
│  + SQLite        │◀──────────────────────────────── │   corre aqui)    │
└─────────────────┘        peers, stats, on/off        └──────────────────┘
```

O painel guarda os metadados dos utilizadores (nome, chaves, IP do túnel,
expiração, etc.) numa base de dados SQLite local — o MikroTik só sabe dos
peers em si (chave pública, IP permitido, estado). As chaves privadas nunca
saem da máquina do painel.

## Pré-requisitos

- Um MikroTik com **RouterOS 7.1+** (suporte nativo a WireGuard) acessível
  por SSH a partir da máquina onde vais instalar o painel.
- Uma conta de utilizador no MikroTik com permissões para gerir interfaces
  WireGuard, endereços IP e firewall (grupo `full` é o mais simples).
- Python 3.10+ na máquina onde o painel vai correr (Linux; testado em
  Raspberry Pi OS / Debian / Ubuntu).

## Instalação

### 1. Configurar o MikroTik

Se ainda não tens uma interface WireGuard no router, usa o script
[`mikrotik-setup.rsc`](mikrotik-setup.rsc) — abre-o, lê as instruções no
topo (é para colar no terminal do Winbox, não por SSH não-interativo) e
ajusta a porta/rede antes de colar.

Se já tens uma interface WireGuard configurada manualmente, só precisas de
garantir que existe uma conta SSH com permissões suficientes.

### 2. Instalar o painel

```bash
git clone https://github.com/<o-teu-user>/wg-manager.git
cd wg-manager
sudo bash install.sh
```

O script pergunta o IP do MikroTik e as credenciais SSH, testa a ligação,
instala as dependências, cria o serviço systemd e arranca o painel. No fim
mostra o URL local para abrires no browser e criares a conta de
administrador (primeira visita).

### 3. Instalação manual (alternativa ao install.sh)

```bash
sudo mkdir -p /opt/wg-manager
sudo cp -r . /opt/wg-manager/
cd /opt/wg-manager
sudo python3 -m venv venv
sudo venv/bin/pip install -r requirements.txt

# Credenciais do MikroTik (não vão no unit do systemd, ficam num ficheiro à parte)
echo "MIKROTIK_PASS=a-tua-password" | sudo tee mikrotik.env
sudo chmod 600 mikrotik.env

sudo cp wg-manager.service /etc/systemd/system/
sudo mkdir -p /etc/systemd/system/wg-manager.service.d
cat <<EOF | sudo tee /etc/systemd/system/wg-manager.service.d/override.conf
[Service]
Environment=MIKROTIK_HOST=192.168.1.1
Environment=MIKROTIK_USER=o-teu-utilizador-ssh
EnvironmentFile=/opt/wg-manager/mikrotik.env
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now wg-manager
```

## Variáveis de ambiente

| Variável | Obrigatória | Descrição |
|---|---|---|
| `MIKROTIK_HOST` | sim | IP do MikroTik na LAN |
| `MIKROTIK_USER` | sim | utilizador SSH do MikroTik |
| `MIKROTIK_PASS` | sim | password desse utilizador (usa `EnvironmentFile`, não a metas direto no unit) |
| `MIKROTIK_SSH_PORT` | não | porta SSH do MikroTik (default `22`) |
| `WG_HOST` | sim | IP público/hostname pelo qual os clientes VPN ligam (o que vai nos `.conf` gerados) |
| `LAN_NETWORK` | não | rede local para o modo "só LAN" (default `192.168.1.0/24`) |
| `SECRET_KEY` | sim | chave de sessão Flask — gera uma fixa (`python3 -c "import secrets; print(secrets.token_hex(32))"`); se não definires, muda a cada reinício e todos são desligados |
| `PORT` | não | porta HTTP do painel (default `5000`) |
| `TELEGRAM_TOKEN` / `TELEGRAM_CHAT_ID` | não | ativa notificação quando um peer liga à VPN |

## Segurança

- Login obrigatório para tudo exceto `/login` e `/setup` (a criação da
  primeira conta).
- Proteção CSRF em todos os formulários.
- As chaves privadas e preshared ficam só na base de dados local — nunca são
  enviadas ao MikroTik (que só precisa da chave pública de cada peer).
- Corre em HTTP simples por omissão (é pensado para uso na LAN/VPN). Se
  quiseres expor isto fora da tua rede, põe um reverse proxy com HTTPS
  (Caddy, nginx, Cloudflare Tunnel) à frente.
- O `mikrotik.env` (password do router) fica com permissões `600`, fora do
  ficheiro do systemd, para não aparecer em `systemctl show`/logs.

## Estrutura do projeto

```
app.py                  # aplicação Flask (rotas + lógica RouterOS via SSH)
templates/              # páginas Jinja2
static/style.css        # estilos
install.sh              # instalador automático
mikrotik-setup.rsc       # script RouterOS para criar a interface WireGuard
rename_from_confs.py    # utilitário: renomear peers em massa a partir de .conf
wg-manager.service      # unit systemd de referência
```

## Licença

Uso pessoal/homelab — adapta como quiseres.

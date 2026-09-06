# =============================================================================
# WireGuard Manager — setup inicial do MikroTik (RouterOS 7+)
# =============================================================================
# Cria a interface WireGuard no router e as regras de firewall/NAT necessárias
# para que o WireGuard Manager (a correr noutra máquina) o consiga gerir.
#
# Como usar:
#   1. Ajusta as variáveis abaixo (porta, IP interno do túnel, nome do
#      bridge/LAN).
#   2. Cola o conteúdo todo de uma vez no terminal do **Winbox** (New Terminal)
#      ou numa sessão **SSH interativa** (`ssh utilizador@router` e depois
#      cola). Não uses `ssh router "$(cat mikrotik-setup.rsc)"` — por SSH
#      não-interativo, o RouterOS trata cada linha como um script à parte e
#      as variáveis `:local` deixam de existir na linha seguinte.
#   3. No router, cria a conta de utilizador que o WireGuard Manager vai usar
#      por SSH: /user add name=wgmanager group=full password=<escolhe uma>
#      (grupo "full" é necessário para poder criar/remover peers).
#
# NOTA: se já tens uma interface WireGuard chamada wg0, ajusta os nomes
# abaixo ou remove as linhas de "add" correspondentes.

# --- Interface WireGuard (gera a própria chave privada automaticamente) ---
:local wgPort 51820
:local wgAddress "10.8.0.1/24"
:local wgNetwork "10.8.0.0/24"
:local lanInterface "bridge"

/interface wireguard add name=wg0 listen-port=$wgPort comment="WireGuard Manager"
/ip address add address=$wgAddress interface=wg0

# --- Firewall: aceitar o WireGuard vindo da Internet ---
/ip firewall filter add chain=input action=accept protocol=udp dst-port=$wgPort in-interface-list=WAN comment="WireGuard" place-before=[find dynamic=no action=drop chain=input]

# --- Firewall: permitir encaminhamento de/para o túnel ---
/ip firewall filter add chain=forward action=accept in-interface=wg0 comment="wg0 forward in"
/ip firewall filter add chain=forward action=accept out-interface=wg0 comment="wg0 forward out"

# --- NAT: mascarar tráfego do túnel quando sai para a LAN (para os clientes
#     VPN aparecerem como vindos do próprio router perante outros serviços
#     da rede que só confiam na sub-rede local) ---
/ip firewall nat add chain=srcnat action=masquerade src-address=$wgNetwork out-interface=$lanInterface comment="wg0 -> LAN masquerade"

:put "Interface wg0 criada. Chave publica do servidor:"
:put [/interface wireguard get [find name=wg0] public-key]

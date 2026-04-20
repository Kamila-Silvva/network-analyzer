import argparse
import math
import csv
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, rdpcap, DNS, DNSQR, IP, TCP
except ImportError:
    print("Instale scapy: sudo apt install python3-scapy")
    exit(1)

ENTROPIA_MAX  = 3.5
QUERY_MAX     = 50
VOLUME_MAX    = 20


def entropia(s): 
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    return round(-sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values()), 2)


def subdominio(nome):
    partes = nome.rstrip('.').split('.')
    return '.'.join(partes[:-2]) if len(partes) > 2 else nome


def analisar(pkt, alertas, contagem):
    if not pkt.haslayer(IP):
        return

    src  = pkt[IP].src
    dst  = pkt[IP].dst
    hora = datetime.now().strftime("%H:%M:%S")

    def alerta(proto, tipo, detalhe):
        alertas.append({"hora": hora, "proto": proto, "tipo": tipo,
                         "src": src, "dst": dst, "detalhe": detalhe})

    if pkt.haslayer(TCP):
        dp = pkt[TCP].dport
        sp = pkt[TCP].sport

        # DNS via TCP em desktop é anomalia — transferência de zona ou tunelamento
        if dp == 53 or sp == 53:
            alerta("DNS", "[CRITICO] TCP/53", "Desktops não usam TCP na porta 53.")

        # LDAP sem criptografia expõe credenciais em texto puro
        if dp == 389 or sp == 389:
            alerta("LDAP", "[CRITICO] LDAP/389", "Tráfego em texto puro. Use LDAPS/636.")

        # LDAPS — comportamento esperado, só registra
        if dp == 636 or sp == 636:
            alerta("LDAPS", "[OK] LDAPS/636", "Tráfego criptografado.")

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode(errors="replace")
        contagem[src] += 1

        if len(query) > QUERY_MAX:
            alerta("DNS", "[AVISO] Query longa", f"{len(query)} chars — possível tunelamento.")

        sub = subdominio(query)
        e   = entropia(sub)
        if e > ENTROPIA_MAX:
            alerta("DNS", "[AVISO] Alta entropia", f"{sub} | entropia: {e}")

        if contagem[src] >= VOLUME_MAX and contagem[src] % VOLUME_MAX == 0:
            alerta("DNS", "[AVISO] Alto volume", f"{contagem[src]} queries de {src}")


def exibir(alertas):
    if not alertas:
        print("\nNenhuma anomalia detectada.")
        return

    criticos = sum(1 for a in alertas if "CRITICO" in a["tipo"])
    avisos   = sum(1 for a in alertas if "AVISO" in a["tipo"])

    print(f"\n{'─' * 60}")
    print(f"  {len(alertas)} evento(s) — {criticos} critico(s), {avisos} aviso(s)")
    print(f"{'─' * 60}")
    for i, a in enumerate(alertas, 1):
        print(f"\n[{i}] {a['tipo']}  ({a['proto']})")
        print(f"    {a['hora']}  {a['src']} -> {a['dst']}")
        print(f"    {a['detalhe']}")
    print(f"\n{'─' * 60}\n")


def salvar(alertas, arquivo="alertas.csv"):
    with open(arquivo, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["hora", "proto", "tipo", "src", "dst", "detalhe"])
        writer.writeheader()
        writer.writerows(alertas)
    print(f"Salvo em {arquivo}")


def modo_pcap(arquivo):
    alertas  = []
    contagem = defaultdict(int)
    try:
        pacotes = rdpcap(arquivo)
    except FileNotFoundError:
        print(f"Arquivo não encontrado: {arquivo}")
        return
    print(f"{len(pacotes)} pacotes carregados de {arquivo}\n")
    for pkt in pacotes:
        analisar(pkt, alertas, contagem)
    exibir(alertas)
    if alertas:
        salvar(alertas)


def modo_live(interface=None, duracao=60):
    alertas  = []
    contagem = defaultdict(int)
    print(f"Capturando em {interface or 'default'} por {duracao}s — Ctrl+C para parar\n")
    try:
        sniff(
            iface=interface,
            filter="port 53 or port 389 or port 636",
            prn=lambda p: analisar(p, alertas, contagem),
            timeout=duracao,
            store=False,
        )
    except (PermissionError, KeyboardInterrupt):
        pass
    exibir(alertas)
    if alertas:
        salvar(alertas)


def main():
    parser = argparse.ArgumentParser(description="Network Analyzer — DNS + LDAP")
    parser.add_argument("-f", "--file",      help="Arquivo .pcap")
    parser.add_argument("-i", "--interface", help="Interface de rede")
    parser.add_argument("-t", "--tempo",     type=int, default=60)
    args = parser.parse_args()

    print("network_analyzer.py | DNS (53) · LDAP (389) · LDAPS (636)")
    print("─" * 60)

    if args.file:
        modo_pcap(args.file)
    else:
        modo_live(args.interface, args.tempo)


if __name__ == "__main__":
    main()

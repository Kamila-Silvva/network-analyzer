# network-analyzer

Script Python para detecção de anomalias em tráfego de rede.

## O que detecta

- TCP na porta 53 — tunelamento DNS / C2
- LDAP na porta 389 — credenciais em texto puro
- Queries DNS longas — possível data exfiltration
- Alta entropia em subdomínios — indicativo de DGA
- LDAPS/636 — registrado como tráfego seguro

## Requisitos

```bash
sudo apt install python3-scapy
```

## Uso

```bash
# Analisar arquivo pcap
sudo python3 network_analyzer.py -f captura.pcap

# Captura ao vivo
sudo python3 network_analyzer.py -i eth0 -t 60
```

## Exemplo de output

```
16 evento(s) — 14 critico(s), 0 aviso(s)

[1] [CRITICO] TCP/53  (DNS)
    192.168.1.11 -> 192.168.1.1
    Desktops não usam TCP na porta 53.

[13] [CRITICO] LDAP/389  (LDAP)
    127.0.0.1 -> 127.0.0.1
    Tráfego em texto puro. Use LDAPS/636.
```

# network-analyzer

Script Python para detecção de anomalias em tráfego de rede, desenvolvido como projeto prático de estudo em Blue Team e análise de protocolos.

---

## O que detecta

| Indicador | Porta | Severidade |
|---|---|---|
| TCP na porta 53 | 53/TCP | Crítico |
| LDAP sem criptografia | 389/TCP | Crítico |
| Query DNS longa (>50 chars) | 53/UDP | Aviso |
| Alta entropia em subdomínios | 53/UDP | Aviso |
| Alto volume de queries por host | 53/UDP | Aviso |
| LDAPS (tráfego seguro) | 636/TCP | Info |

---

## Requisitos

```bash
sudo apt install python3-scapy
```

---

## Uso

```bash
# Analisar arquivo .pcap
sudo python3 network_analyzer.py -f captura.pcap

# Captura ao vivo (60s por padrão)
sudo python3 network_analyzer.py -i eth0 -t 60
```

---

## Exemplo de output

```
────────────────────────────────────────────────────────────
  4 evento(s) — 2 critico(s), 2 aviso(s)
────────────────────────────────────────────────────────────

[1] [CRITICO] TCP/53  (DNS)
    14:32:01  192.168.1.11 -> 192.168.1.1
    Desktops não usam TCP na porta 53.

[2] [CRITICO] LDAP/389  (LDAP)
    14:32:04  127.0.0.1 -> 127.0.0.1
    Tráfego em texto puro. Use LDAPS/636.

[3] [AVISO] Query longa  (DNS)
    14:32:07  192.168.1.11 -> 8.8.8.8
    63 chars — possível tunelamento.

[4] [AVISO] Alta entropia  (DNS)
    14:32:09  192.168.1.11 -> 8.8.8.8
    a7f3kqzx92.example.com | entropia: 3.87
```

Os alertas são salvos automaticamente em `alertas.csv`.

---

## Limitações conhecidas

- **TCP/53** é tratado como crítico em qualquer caso. Em ambientes reais, respostas DNS grandes podem fazer fallback legítimo para TCP - ajuste o threshold conforme o contexto da rede.
- Desenvolvido e testado em ambiente de lab local. Não substitui ferramentas de monitoramento de produção (Zeek, Suricata, etc.).

---

## Aviso legal

Use apenas em redes e dispositivos que você tem autorização para monitorar. A captura de tráfego sem autorização pode violar leis locais.

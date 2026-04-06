# 🔍 Network Port Scanner

Ferramenta de varredura de portas desenvolvida em Python com suporte a **SYN scan** (via Scapy) e **TCP Connect scan**, com **banner grabbing** para fingerprinting de serviços.

Desenvolvida como projeto de aprendizado na área de **cibersegurança ofensiva**, simulando funcionalidades básicas de ferramentas como o Nmap.

---

## ⚙️ Funcionalidades

- **SYN Scan** via Scapy — varredura furtiva sem completar o handshake TCP
- **TCP Connect Scan** — fallback automático sem necessidade de root
- **Banner Grabbing** — identifica versão e tipo do serviço em portas abertas
- **Identificação automática** de serviços conhecidos (HTTP, SSH, FTP, RDP, etc.)
- **Varredura paralela** com threads configuráveis para maior velocidade
- **Relatório em arquivo** `.txt` com resultado estruturado
- Suporte a ranges, listas e portas comuns

---

## 🚀 Instalação

```bash
# Clone o repositório
git clone https://github.com/gabriel-vieira/network-port-scanner
cd network-port-scanner

# Instale as dependências
pip install -r requirements.txt
```

---

## 📖 Uso

```bash
# Varredura nas portas mais comuns
python scanner.py 192.168.1.1

# Range de portas
python scanner.py 192.168.1.1 -p 1-1024

# Portas específicas
python scanner.py 192.168.1.1 -p 22,80,443,3306

# SYN scan (requer root/sudo)
sudo python scanner.py 192.168.1.1 --syn

# Salvar relatório
python scanner.py 192.168.1.1 -o resultado.txt

# Ajustar velocidade (mais threads = mais rápido)
python scanner.py 192.168.1.1 -T 200 -t 0.5
```

### Parâmetros

| Parâmetro | Descrição | Padrão |
|-----------|-----------|--------|
| `target` | IP ou hostname do alvo | — |
| `-p` | Portas: `80`, `1-1024`, `80,443`, `common` | `common` |
| `-t` | Timeout por porta (segundos) | `1.0` |
| `-T` | Número de threads paralelas | `100` |
| `--syn` | Ativa SYN scan via Scapy (root) | TCP Connect |
| `--no-banner` | Desativa banner grabbing | — |
| `-o` | Arquivo de saída do relatório | — |

---

## 🖥️ Exemplo de saída

```
[*] Modo: TCP Connect Scan
[*] Alvo : 192.168.1.1 (192.168.1.1)
[*] Portas: 17 porta(s) para varrer
--------------------------------------------------
[ABERTA] Porta 22/tcp (SSH) — SSH-2.0-OpenSSH_8.9
[ABERTA] Porta 80/tcp (HTTP) — HTTP/1.1 200 OK
[ABERTA] Porta 443/tcp (HTTPS)
--------------------------------------------------
Varredura concluída. 3 porta(s) aberta(s) de 17 verificada(s).
```

---

## 🧠 Conceitos aplicados

- **SYN Scan**: envia pacote TCP com flag SYN e aguarda SYN-ACK, sem completar o three-way handshake — técnica furtiva clássica de reconhecimento
- **Banner Grabbing**: após identificar porta aberta, envia requisição básica e captura a resposta inicial do serviço para fingerprinting
- **Threading**: varredura paralela para reduzir tempo total de execução

---

## ⚠️ Aviso legal

Esta ferramenta foi desenvolvida para fins **educacionais** e deve ser utilizada **apenas em redes e sistemas com autorização explícita**. O uso em ambientes sem permissão pode ser ilegal.

---

## 👨‍💻 Autor

**Gabriel Vieira** — 
[LinkedIn](https://www.linkedin.com/in/gabriel-vieira-de-sousa-330b55249/) 
[TryHackMe](https://tryhackme.com/p/legacy.sousa)

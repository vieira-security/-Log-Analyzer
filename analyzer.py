#!/usr/bin/env python3
"""
Log Analyzer
Análise de logs de acesso em servidores Linux para detecção
de padrões suspeitos e tentativas de intrusão.
Autor: Gabriel Vieira
"""

import re
import argparse
import sys
import datetime
from collections import defaultdict, Counter
from pathlib import Path

# --- Cores para terminal ---
class Colors:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

# --- Thresholds de detecção ---
BRUTE_FORCE_THRESHOLD = 10   # tentativas falhas por IP
SCANNER_THRESHOLD     = 20   # requisições em paths inválidos por IP
DOS_THRESHOLD         = 500  # requisições totais por IP

# --- Regex para log no formato Combined Log Format (Apache/Nginx) ---
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'           # IP do cliente
    r'\S+\s+\S+\s+'             # ident, authuser
    r'\[(?P<time>[^\]]+)\]\s+'  # timestamp
    r'"(?P<method>\S+)\s+'      # método HTTP
    r'(?P<path>\S+)\s+'         # path requisitado
    r'\S+"\s+'                  # protocolo
    r'(?P<status>\d{3})\s+'     # código de status
    r'(?P<size>\S+)'            # tamanho da resposta
)

# Paths suspeitos que scanners costumam testar
SUSPICIOUS_PATHS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config",
    "/etc/passwd", "/shell", "/cmd", "/eval", "/../",
    "/wp-login", "/.git", "/backup", "/db", "/sql",
]


def print_banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
  _                  _                _           
 | |                / \   _ __   __ _| |_   _ ____
 | |    ___  __ _  / _ \ | '_ \ / _` | | | | |_  /
 | |___/ _ \/ _` |/ ___ \| | | | (_| | | |_| |/ / 
 |_____\___/\__, /_/   \_\_| |_|\__,_|_|\__, /___|
             |___/                       |___/     
{Colors.RESET}
{Colors.YELLOW}  Log Analyzer — Detecção de Intrusão | by Gabriel Vieira{Colors.RESET}
""")


def parse_line(line: str) -> dict | None:
    """Faz parse de uma linha de log. Retorna dict ou None se inválida."""
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    return match.groupdict()


def is_suspicious_path(path: str) -> bool:
    """Verifica se o path requisitado é suspeito."""
    path_lower = path.lower()
    return any(s in path_lower for s in SUSPICIOUS_PATHS)


def analyze(log_path: str, start_date: str = None, end_date: str = None) -> dict:
    """
    Lê e analisa o arquivo de log.
    Retorna dicionário com todas as métricas coletadas.
    """
    path = Path(log_path)
    if not path.exists():
        print(f"{Colors.RED}[ERRO] Arquivo não encontrado: {log_path}{Colors.RESET}")
        sys.exit(1)

    # Contadores
    total_lines       = 0
    parsed_lines      = 0
    ip_requests       = defaultdict(int)          # total de requisições por IP
    ip_failed_auth    = defaultdict(int)          # erros 401/403 por IP
    ip_not_found      = defaultdict(int)          # erros 404 por IP
    ip_suspicious     = defaultdict(int)          # paths suspeitos por IP
    status_counter    = Counter()                 # contagem por status HTTP
    path_counter      = Counter()                 # paths mais acessados
    method_counter    = Counter()                 # métodos HTTP
    hourly_requests   = Counter()                 # requisições por hora
    error_ips         = defaultdict(list)         # IPs com erros 5xx

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_lines += 1
            entry = parse_line(line.strip())
            if not entry:
                continue
            parsed_lines += 1

            ip     = entry["ip"]
            status = int(entry["status"])
            method = entry["method"]
            rpath  = entry["path"]
            time   = entry["time"]

            # Filtro de data (opcional)
            if start_date or end_date:
                try:
                    # Formato Apache: 10/Oct/2023:13:55:36 +0000
                    log_date = datetime.datetime.strptime(time[:11], "%d/%b/%Y")
                    if start_date and log_date < datetime.datetime.strptime(start_date, "%Y-%m-%d"):
                        continue
                    if end_date and log_date > datetime.datetime.strptime(end_date, "%Y-%m-%d"):
                        continue
                except Exception:
                    pass

            # Acumula métricas
            ip_requests[ip] += 1
            status_counter[status] += 1
            method_counter[method] += 1
            path_counter[rpath] += 1

            # Erros de autenticação
            if status in (401, 403):
                ip_failed_auth[ip] += 1

            # Não encontrado
            if status == 404:
                ip_not_found[ip] += 1

            # Erros de servidor
            if status >= 500:
                error_ips[ip].append(rpath)

            # Paths suspeitos
            if is_suspicious_path(rpath):
                ip_suspicious[ip] += 1

            # Hora da requisição
            try:
                hour = time[12:14]
                hourly_requests[hour] += 1
            except Exception:
                pass

    return {
        "total_lines":     total_lines,
        "parsed_lines":    parsed_lines,
        "ip_requests":     ip_requests,
        "ip_failed_auth":  ip_failed_auth,
        "ip_not_found":    ip_not_found,
        "ip_suspicious":   ip_suspicious,
        "status_counter":  status_counter,
        "path_counter":    path_counter,
        "method_counter":  method_counter,
        "hourly_requests": hourly_requests,
        "error_ips":       error_ips,
    }


def detect_threats(data: dict) -> list:
    """
    Aplica regras de detecção e retorna lista de alertas.
    Cada alerta tem: tipo, ip, contagem, severidade.
    """
    alerts = []

    for ip, count in data["ip_failed_auth"].items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "type":     "BRUTE FORCE",
                "ip":       ip,
                "count":    count,
                "severity": "ALTO",
                "detail":   f"{count} tentativas de autenticação falha (401/403)"
            })

    for ip, count in data["ip_suspicious"].items():
        if count >= SCANNER_THRESHOLD:
            alerts.append({
                "type":     "SCANNER",
                "ip":       ip,
                "count":    count,
                "severity": "ALTO",
                "detail":   f"{count} requisições em paths suspeitos"
            })
        elif count >= 5:
            alerts.append({
                "type":     "RECONHECIMENTO",
                "ip":       ip,
                "count":    count,
                "severity": "MÉDIO",
                "detail":   f"{count} requisições em paths suspeitos"
            })

    for ip, count in data["ip_requests"].items():
        if count >= DOS_THRESHOLD:
            alerts.append({
                "type":     "POSSÍVEL DoS",
                "ip":       ip,
                "count":    count,
                "severity": "CRÍTICO",
                "detail":   f"{count} requisições totais — volume anormal"
            })

    for ip, paths in data["error_ips"].items():
        if len(paths) >= 10:
            alerts.append({
                "type":     "ERROS DE SERVIDOR",
                "ip":       ip,
                "count":    len(paths),
                "severity": "BAIXO",
                "detail":   f"{len(paths)} erros 5xx gerados"
            })

    # Ordena por severidade
    order = {"CRÍTICO": 0, "ALTO": 1, "MÉDIO": 2, "BAIXO": 3}
    alerts.sort(key=lambda x: order.get(x["severity"], 99))
    return alerts


def print_report(data: dict, alerts: list, top_n: int = 10):
    """Exibe relatório completo no terminal."""

    # --- Resumo geral ---
    print(f"\n{Colors.BOLD}{'='*55}{Colors.RESET}")
    print(f"{Colors.BOLD}  RESUMO GERAL{Colors.RESET}")
    print(f"{'='*55}")
    print(f"  Linhas no arquivo : {data['total_lines']}")
    print(f"  Linhas analisadas : {data['parsed_lines']}")
    print(f"  IPs únicos        : {len(data['ip_requests'])}")
    print(f"  Requisições totais: {sum(data['ip_requests'].values())}")

    # --- Status HTTP ---
    print(f"\n{Colors.BOLD}{'='*55}{Colors.RESET}")
    print(f"{Colors.BOLD}  DISTRIBUIÇÃO DE STATUS HTTP{Colors.RESET}")
    print(f"{'='*55}")
    for status, count in sorted(data["status_counter"].items()):
        bar = "█" * min(count // 10, 30)
        color = Colors.GREEN if status < 400 else (Colors.YELLOW if status < 500 else Colors.RED)
        print(f"  {color}{status}{Colors.RESET}  {bar} {count}")

    # --- Top IPs ---
    print(f"\n{Colors.BOLD}{'='*55}{Colors.RESET}")
    print(f"{Colors.BOLD}  TOP {top_n} IPs POR REQUISIÇÕES{Colors.RESET}")
    print(f"{'='*55}")
    top_ips = sorted(data["ip_requests"].items(), key=lambda x: x[1], reverse=True)[:top_n]
    for ip, count in top_ips:
        print(f"  {Colors.CYAN}{ip:<20}{Colors.RESET} {count} requisições")

    # --- Top paths ---
    print(f"\n{Colors.BOLD}{'='*55}{Colors.RESET}")
    print(f"{Colors.BOLD}  TOP {top_n} PATHS MAIS ACESSADOS{Colors.RESET}")
    print(f"{'='*55}")
    for path, count in data["path_counter"].most_common(top_n):
        flag = f" {Colors.RED}[SUSPEITO]{Colors.RESET}" if is_suspicious_path(path) else ""
        print(f"  {count:<8} {path[:45]}{flag}")

    # --- Métodos HTTP ---
    print(f"\n{Colors.BOLD}{'='*55}{Colors.RESET}")
    print(f"{Colors.BOLD}  MÉTODOS HTTP{Colors.RESET}")
    print(f"{'='*55}")
    for method, count in data["method_counter"].most_common():
        print(f"  {method:<10} {count}")

    # --- Alertas de segurança ---
    print(f"\n{Colors.BOLD}{'='*55}{Colors.RESET}")
    print(f"{Colors.BOLD}  ALERTAS DE SEGURANÇA{Colors.RESET}")
    print(f"{'='*55}")

    if not alerts:
        print(f"  {Colors.GREEN}Nenhuma ameaça detectada.{Colors.RESET}")
    else:
        sev_colors = {
            "CRÍTICO": Colors.RED,
            "ALTO":    Colors.RED,
            "MÉDIO":   Colors.YELLOW,
            "BAIXO":   Colors.CYAN,
        }
        for alert in alerts:
            color = sev_colors.get(alert["severity"], Colors.RESET)
            print(
                f"\n  {color}[{alert['severity']}]{Colors.RESET} "
                f"{Colors.BOLD}{alert['type']}{Colors.RESET}"
            )
            print(f"  IP     : {alert['ip']}")
            print(f"  Detalhe: {alert['detail']}")


def save_report(data: dict, alerts: list, output_file: str, log_path: str, top_n: int = 10):
    """Salva relatório em arquivo .txt."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_file, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("         RELATÓRIO DE ANÁLISE DE LOG\n")
        f.write("=" * 60 + "\n")
        f.write(f"Arquivo  : {log_path}\n")
        f.write(f"Data/Hora: {timestamp}\n")
        f.write(f"Linhas analisadas: {data['parsed_lines']} / {data['total_lines']}\n")
        f.write(f"IPs únicos       : {len(data['ip_requests'])}\n")
        f.write("=" * 60 + "\n\n")

        f.write("TOP IPs\n" + "-" * 40 + "\n")
        for ip, count in sorted(data["ip_requests"].items(), key=lambda x: x[1], reverse=True)[:top_n]:
            f.write(f"{ip:<20} {count} requisições\n")

        f.write("\nSTATUS HTTP\n" + "-" * 40 + "\n")
        for status, count in sorted(data["status_counter"].items()):
            f.write(f"{status}  {count}\n")

        f.write("\nALERTAS DE SEGURANÇA\n" + "-" * 40 + "\n")
        if not alerts:
            f.write("Nenhuma ameaça detectada.\n")
        else:
            for alert in alerts:
                f.write(f"\n[{alert['severity']}] {alert['type']}\n")
                f.write(f"IP     : {alert['ip']}\n")
                f.write(f"Detalhe: {alert['detail']}\n")

    print(f"\n{Colors.CYAN}[*] Relatório salvo em: {output_file}{Colors.RESET}")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Analisa logs de acesso Apache/Nginx e detecta padrões suspeitos"
    )
    parser.add_argument("logfile", help="Caminho para o arquivo de log")
    parser.add_argument(
        "--top", type=int, default=10,
        help="Quantidade de resultados no top (padrão: 10)"
    )
    parser.add_argument(
        "--start", help="Data inicial do filtro (formato: YYYY-MM-DD)"
    )
    parser.add_argument(
        "--end", help="Data final do filtro (formato: YYYY-MM-DD)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Salvar relatório em arquivo .txt"
    )
    parser.add_argument(
        "--brute-threshold", type=int, default=BRUTE_FORCE_THRESHOLD,
        help=f"Tentativas para alertar brute force (padrão: {BRUTE_FORCE_THRESHOLD})"
    )
    parser.add_argument(
        "--dos-threshold", type=int, default=DOS_THRESHOLD,
        help=f"Requisições para alertar DoS (padrão: {DOS_THRESHOLD})"
    )

    args = parser.parse_args()

    # Permite customizar thresholds via CLI
    global BRUTE_FORCE_THRESHOLD, DOS_THRESHOLD
    BRUTE_FORCE_THRESHOLD = args.brute_threshold
    DOS_THRESHOLD         = args.dos_threshold

    print(f"{Colors.CYAN}[*] Analisando: {args.logfile}{Colors.RESET}")
    if args.start or args.end:
        print(f"{Colors.CYAN}[*] Filtro de data: {args.start or '?'} → {args.end or '?'}{Colors.RESET}")

    data   = analyze(args.logfile, args.start, args.end)
    alerts = detect_threats(data)

    print_report(data, alerts, args.top)

    if args.output:
        save_report(data, alerts, args.output, args.logfile, args.top)


if __name__ == "__main__":
    main()

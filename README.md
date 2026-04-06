# 🛡️ Log Analyzer

Ferramenta de análise de logs de acesso em servidores Linux (Apache/Nginx) para **detecção de padrões suspeitos e tentativas de intrusão**.

Desenvolvida como projeto de aprendizado na área de **Blue Team / SOC**, simulando tarefas reais de um analista de segurança no monitoramento de logs.

---

## ⚙️ Funcionalidades

- **Detecção de Brute Force** — IPs com muitas tentativas de autenticação falha (401/403)
- **Detecção de Scanner** — IPs requisitando paths suspeitos (`.env`, `/admin`, `/phpmyadmin`, etc.)
- **Detecção de DoS** — IPs com volume anormal de requisições
- **Análise de erros 5xx** — identifica IPs que geram erros no servidor
- **Top IPs e paths** mais acessados
- **Distribuição de status HTTP** com visualização em barra
- **Filtro por período** de data
- **Relatório exportável** em `.txt`
- Thresholds configuráveis via argumentos

---

## 🚀 Instalação

```bash
# Clone o repositório
git clone https://github.com/gabriel-vieira/log-analyzer
cd log-analyzer

# Sem dependências externas — apenas Python 3.8+
python analyzer.py --help
```

---

## 📖 Uso

```bash
# Análise básica
python analyzer.py access.log

# Filtrar por período
python analyzer.py access.log --start 2023-10-01 --end 2023-10-31

# Salvar relatório
python analyzer.py access.log -o relatorio.txt

# Ajustar thresholds de detecção
python analyzer.py access.log --brute-threshold 5 --dos-threshold 200

# Testar com o log de exemplo incluído
python analyzer.py sample.log
```

### Parâmetros

| Parâmetro | Descrição | Padrão |
|-----------|-----------|--------|
| `logfile` | Caminho para o arquivo de log | — |
| `--top` | Quantidade de resultados no top | `10` |
| `--start` | Data inicial do filtro (`YYYY-MM-DD`) | — |
| `--end` | Data final do filtro (`YYYY-MM-DD`) | — |
| `--brute-threshold` | Tentativas para alertar brute force | `10` |
| `--dos-threshold` | Requisições para alertar DoS | `500` |
| `-o` | Arquivo de saída do relatório | — |

---

## 🖥️ Exemplo de saída

```
=======================================================
  ALERTAS DE SEGURANÇA
=======================================================

  [ALTO] BRUTE FORCE
  IP     : 10.0.0.5
  Detalhe: 10 tentativas de autenticação falha (401/403)

  [MÉDIO] RECONHECIMENTO
  IP     : 203.0.113.42
  Detalhe: 7 requisições em paths suspeitos
```

---

## 🧠 Conceitos aplicados

- **Análise de logs**: leitura e parsing de logs no formato Combined Log Format (Apache/Nginx)
- **Detecção de anomalias**: regras baseadas em thresholds para identificar comportamentos fora do padrão
- **Reconhecimento de padrões**: identificação de paths utilizados por scanners automáticos
- **Blue Team / SOC**: simulação de tarefa real de monitoramento e triagem de alertas

---

## 📋 Formato de log suportado

O analyzer suporta o formato **Combined Log Format**, padrão do Apache e Nginx:

```
192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1024
```

---

## ⚠️ Aviso legal

Esta ferramenta foi desenvolvida para fins **educacionais e defensivos**. Utilize apenas em logs de sistemas sob sua responsabilidade ou com autorização explícita.

---

## 👨‍💻 Autor

**Gabriel Vieira** — 
[LinkedIn](https://www.linkedin.com/in/gabriel-vieira-de-sousa-330b55249/) 
[TryHackMe](https://tryhackme.com/p/legacy.sousa)

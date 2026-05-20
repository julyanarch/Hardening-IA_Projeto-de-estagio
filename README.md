# MIND Hardening Sensor

Base de scripts para **varredura**, **analise de risco** e **sanitizacao de usuarios** em ambientes Linux.

O projeto foi criado como uma fundacao para transformar conhecimento operacional humano em dados estruturados que possam alimentar uma IA interna, chamada **MIND**. A proposta e coletar evidencias reais dos servidores, gerar relatorios em texto e JSON, e permitir que a IA responda perguntas operacionais e de seguranca com base em fatos do ambiente.

## Objetivo Estrategico

> Transformar conhecimento operacional humano em inteligencia consumivel por IA.

Na pratica, este projeto ajuda a:

- Padronizar verificacoes de seguranca e operacao em servidores Linux.
- Gerar evidencias tecnicas em formato estruturado.
- Apoiar analises de hardening.
- Reduzir dependencia de verificacoes manuais.
- Criar uma base para futuras automacoes com Ansible.
- Alimentar a IA interna com dados reais dos ambientes dos clientes.

## O Que O Projeto Responde

Com os dados gerados pelos scripts, a IA interna pode responder perguntas como:

- Quais discos estao cheios ou em risco?
- Existem usuarios com permissoes acima do necessario?
- O servidor possui portas abertas?
- O SSH permite login como root?
- Existem servicos falhando?
- Existem muitos updates pendentes?
- Algum usuario foi bloqueado ou removido por chamado?

## Arquitetura

O projeto esta dividido em tres componentes principais:

| Componente | Arquivo | Funcao |
| --- | --- | --- |
| Sensor de varredura | `mind_scan.sh` | Coleta evidencias do servidor Linux e gera TXT/JSON |
| Analisador de risco | `mind_analyzer.py` | Le o JSON do sensor e classifica risco, achados e recomendacoes |
| Sanitizador de usuarios | `mind_sanitize_users.sh` | Le CSV de chamados e bloqueia/remove usuarios Linux |

## 1. Sensor De Varredura

Arquivo:

```bash
mind_scan.sh
```

O `mind_scan.sh` roda no servidor Linux e coleta evidencias de sistema, operacao e seguranca.

Ele verifica:

- Informacoes do sistema operacional.
- Kernel, uptime, CPU e memoria.
- Uso de disco.
- Uso de inodes.
- Usuarios com UID 0.
- Usuarios em grupos privilegiados, como `sudo` e `wheel`.
- Configuracoes de SSH.
- Portas e servicos em escuta.
- Arquivos world-writable.
- Integridade de `/etc/passwd` e `/etc/shadow`.
- Firewall.
- Servicos `systemd` com falha.
- Logs com palavras-chave de erro.
- Updates pendentes.
- Repositorios configurados.

Saidas geradas:

```bash
/var/log/mind/mind_scan_HOST_DATA.txt
/var/log/mind/mind_scan_HOST_DATA.json
```

O arquivo `.txt` serve para leitura humana.  
O arquivo `.json` serve para consumo pelo analisador, pela IA interna ou por futuras automacoes.

## 2. Analisador De Risco

Arquivo:

```bash
mind_analyzer.py
```

O `mind_analyzer.py` le o JSON gerado pelo `mind_scan.sh` e transforma as evidencias em uma analise objetiva.

Ele gera:

- Nivel de risco do host.
- Score de risco.
- Lista de achados.
- Recomendacoes.
- Contexto estruturado para a IA interna.

Exemplo de saida:

```bash
mind_risk_nome_do_arquivo.json
```

Esse resultado ajuda a responder perguntas como:

- Qual host esta em risco alto?
- Qual particao esta acima de 90%?
- Quais usuarios possuem privilegios administrativos?
- Quais portas sensiveis estao abertas?
- O firewall esta ausente ou sem regra?

## 3. Sanitizador De Usuarios

Arquivo:

```bash
mind_sanitize_users.sh
```

O `mind_sanitize_users.sh` executa a parte de sanitizacao relacionada a usuarios Linux.

Ele le um CSV vindo de um chamado interno, valida os usuarios e pode:

- Bloquear uma conta.
- Remover uma conta.
- Remover uma conta junto com a home.
- Registrar tudo em TXT e JSON.

Esse modulo foi separado da varredura por seguranca e organizacao:

- `mind_scan.sh` observa e coleta.
- `mind_sanitize_users.sh` executa acoes de sanitizacao.

A documentacao detalhada desse fluxo esta em:

```bash
README_sanitize_users.md
```

## Fluxo Geral

```text
Servidor Linux
     |
     v
mind_scan.sh
     |
     v
Relatorio TXT + JSON estruturado
     |
     v
mind_analyzer.py
     |
     v
Risco, achados, recomendacoes e contexto para IA
```

Fluxo complementar de offboarding:

```text
Chamado interno / CSV
     |
     v
mind_sanitize_users.sh
     |
     v
Bloqueio ou remocao de usuario + evidencia TXT/JSON
```

## Como Usar

### 1. Executar A Varredura

No servidor Linux:

```bash
chmod +x mind_scan.sh
sudo ./mind_scan.sh
```

Arquivos esperados:

```bash
/var/log/mind/mind_scan_HOST_DATA.txt
/var/log/mind/mind_scan_HOST_DATA.json
```

### 2. Executar O Analisador

Use o JSON gerado pelo sensor:

```bash
python3 mind_analyzer.py /var/log/mind/mind_scan_HOST_DATA.json
```

O analisador gera um novo JSON com risco, achados e recomendacoes.

### 3. Executar Sanitizacao De Usuarios

Para o fluxo de bloqueio ou remocao de usuarios via CSV, consulte:

[README_sanitize_users.md](README_sanitize_users.md)

Resumo:

```bash
sudo ./mind_sanitize_users.sh --csv usuarios.csv --dry-run
sudo ./mind_sanitize_users.sh --csv usuarios.csv --apply
```

O `--dry-run` apenas simula.  
O `--apply` executa a alteracao real.

## Estrutura Dos Arquivos

```text
.
├── mind_scan.sh
├── mind_analyzer.py
├── mind_sanitize_users.sh
├── README.md
├── README_sanitize_users.md
├── anotações.txt
├── .gitignore
└── scripts/
    └── auto_commit.ps1
```

| Arquivo | Descricao |
| --- | --- |
| `mind_scan.sh` | Sensor de coleta e varredura do Linux |
| `mind_analyzer.py` | Analisador de risco a partir do JSON do sensor |
| `mind_sanitize_users.sh` | Sanitizador de usuarios via CSV |
| `README.md` | Visao geral do projeto |
| `README_sanitize_users.md` | Manual detalhado da sanitizacao de usuarios |
| `anotações.txt` | Comandos auxiliares usados no ambiente de teste |
| `scripts/auto_commit.ps1` | Script auxiliar para auto-commit em ambiente local |

## Exemplo De Valor Para A IA

Com os JSONs gerados, a IA interna pode receber dados estruturados e responder com base em fatos coletados do servidor.

Exemplos:

- "Quais discos estao acima de 90%?"
- "Existe algum usuario alem de root com UID 0?"
- "Quais usuarios estao no grupo sudo?"
- "Quais portas estao abertas neste servidor?"
- "O SSH esta permitindo login root?"
- "Algum usuario foi removido por chamado?"

## Requisitos

Ambiente recomendado:

- Linux para execucao dos scripts de varredura e sanitizacao.
- Bash.
- Python 3 para o analisador.
- Permissao de root para coletas sensiveis e acoes de sanitizacao.

Ferramentas usadas quando disponiveis:

- `df`
- `ss` ou `netstat`
- `getent`
- `systemctl`
- `iptables` ou `ufw`
- `apt`, `yum` ou `dnf`

## Seguranca

O projeto lida com informacoes sensiveis do servidor.

Recomendacoes:

- Revise os JSONs antes de compartilhar externamente.
- Nao suba CSVs reais de desligamento para o GitHub.
- Rode `mind_sanitize_users.sh` primeiro com `--dry-run`.
- Use `--apply` apenas depois de validar a simulacao.
- Mantenha os relatorios em local protegido.

O `.gitignore` ja ignora arquivos CSV e relatorios gerados para reduzir o risco de publicar dados sensiveis por acidente.

## Limitacoes Atuais

- Os scripts devem ser testados em ambiente Linux real.
- Algumas coletas precisam de permissao de root.
- O analisador usa regras fixas de risco.
- A validacao de repositorios autorizados ainda depende de uma politica interna.
- A integracao com Ansible ainda e uma evolucao futura.
- A integracao direta com o sistema interno de chamados ainda nao esta automatizada.

## Proximos Passos

- Criar whitelist corporativa de usuarios, portas e repositorios.
- Integrar com playbooks Ansible.
- Criar perfis de risco por tipo de servidor.
- Guardar historico entre execucoes.
- Integrar os JSONs com a base de conhecimento da IA interna.
- Automatizar a importacao de CSVs gerados pelo sistema de chamados.


# MIND Operacao Pratica

Guia de implantacao e execucao para os dois fluxos do projeto:

- governanca de acessos via planilha SharePoint Online / Excel Online;
- sanitizacao do ambiente Linux com varredura, analise e offboarding.

## 1. Visao geral

O desenho recomendado e:

```text
SharePoint Online / Excel Online
        |
        v
Workbook de acessos (.xlsx)
        |
        v
mind_access_sync.py
        |
        v
Plano de sincronizacao TXT/JSON
```

```text
Servidor Linux
        |
        v
mind_scan.sh
        |
        v
mind_analyzer.py
        |
        v
mind_sanitize_users.sh
```

## 2. Preparacao da planilha

O workbook deve ser publicado como arquivo Excel comum no SharePoint Online.

Recomendacoes:

- usar o Excel Online como interface visual;
- restringir permissao de edicao a equipe responsavel;
- manter os campos padronizados;
- sincronizar uma copia local apenas quando o planner precisar ser executado.

## 3. Governanca de acessos

### 3.1 Gerar ou recriar a planilha exemplo

```bash
python3 mind_access_sync.py --create-template --template-path /opt/mind/acessos_exemplo.xlsx
```

### 3.2 Rodar o planner

```bash
python3 mind_access_sync.py --workbook /opt/mind/acessos_exemplo.xlsx --sheet Acessos
```

Saida esperada:

- TXT com leitura humana;
- JSON com diff e entradas normalizadas;
- lista de usuarios para `criar`, `manter` e `remover`.

### 3.3 Interpretacao operacional

- `criar`: usuario esta na planilha e nao existe no host;
- `manter`: usuario esta na planilha e ja existe no host;
- `remover`: usuario saiu da planilha e deve entrar na fila de sanitizacao.

## 4. Sanitizacao do ambiente

### 4.1 Instalar os scripts

```bash
sudo mkdir -p /opt/mind
sudo cp mind_scan.sh mind_analyzer.py mind_sanitize_users.sh /opt/mind/
sudo chmod +x /opt/mind/mind_scan.sh /opt/mind/mind_sanitize_users.sh
```

### 4.2 Execucao manual

Sensor:

```bash
sudo /opt/mind/mind_scan.sh
```

Analise:

```bash
python3 /opt/mind/mind_analyzer.py "$(ls -t /var/log/mind/mind_scan_*.json | head -n 1)"
```

Bloqueio imediato via plano da planilha:

```bash
sudo /opt/mind/mind_sanitize_users.sh --plan-json "$(ls -t /var/log/mind/mind_access_sync_*.json | head -n 1)" --apply
```

Retencao e purge apos 90 dias:

```bash
sudo /opt/mind/mind_sanitize_users.sh --process-retention --apply
```

## 5. Politica de 90 dias

Fluxo esperado:

1. o usuario sai da planilha;
2. o planner registra o usuario em `remover`;
3. o sanitizador bloqueia a conta imediatamente;
4. o estado de retencao e salvo em `/var/lib/mind/mind_sanitize_users_state.json`;
5. depois de 90 dias, o purge definitivo e executado pela rotina de retencao.

## 6. Cron diario

Exemplo de `crontab` para o root:

```cron
0 2 * * * /opt/mind/mind_scan.sh >> /var/log/mind/cron_mind_scan.log 2>&1
15 2 * * * /usr/bin/python3 /opt/mind/mind_analyzer.py "$(ls -t /var/log/mind/mind_scan_*.json | head -n 1)" >> /var/log/mind/cron_mind_analyzer.log 2>&1
30 2 * * * /opt/mind/mind_sanitize_users.sh --process-retention --apply >> /var/log/mind/cron_mind_retention.log 2>&1
```

Observacoes:

- `mind_scan.sh` pode rodar diariamente;
- `mind_analyzer.py` consome o JSON mais recente;
- `mind_sanitize_users.sh --process-retention` faz a purga de contas ja
  bloqueadas e fora do prazo;
- `mind_sanitize_users.sh --plan-json` deve ser executado quando houver novo
  diff da planilha.

## 7. Caminho de implantacao

1. Publicar a planilha no SharePoint.
2. Definir permissao de edicao e aprovacao.
3. Instalar os scripts em `/opt/mind`.
4. Rodar o planner para validar o workbook.
5. Agendar sensor, analise e retencao diaria via `cron`.
6. Usar o sanitizador manualmente apenas em cenarios de excecao ou chamada
   pontual.

## 8. Evolucao futura

- conexao direta com SharePoint Online;
- execucao via playbook Ansible;
- historico de acessos e retencao;
- politicas por grupo ou tipo de servidor;
- integracao com base de conhecimento da IA interna.

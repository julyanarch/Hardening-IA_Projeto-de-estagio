# MIND User Sanitizer

Documento de referencia para a sanitizacao de usuarios Linux.

O sanitizador faz parte da trilha operacional do projeto e atua em tres
cenarios:

- fluxo legado com CSV manual;
- fluxo automatizado com JSON gerado pelo planner de acessos;
- rotina de retencao para purge apos 90 dias.

## Funcao

O script `mind_sanitize_users.sh` executa acoes administrativas em contas Linux
com base em entradas validas. O objetivo e padronizar bloqueio, remocao e
retencao de forma auditavel.

## Acoes suportadas

- `lock`: bloqueia a conta e expira o acesso;
- `remove`: remove o usuario, com ou sem home;
- `purge`: remove usuario e home;
- `--plan-json`: recebe o diff gerado pelo planner de acessos e bloqueia
  usuarios que sairam da planilha;
- `--process-retention`: percorre o estado persistente e remove contas que ja
  completaram o prazo de 90 dias.

## Estrutura de dados

### CSV legado

```csv
username,action,remove_home,reason,ticket
```

### JSON do planner

O planner de acessos gera um JSON com uma secao `diff`, onde o campo
`to_remove` representa os usuarios que devem entrar em sanitizacao imediata.

## Politica de retencao

O fluxo adotado para usuarios removidos da planilha e:

1. a conta e bloqueada imediatamente;
2. a data do bloqueio e gravada em `/var/lib/mind/mind_sanitize_users_state.json`;
3. apos 90 dias, o `--process-retention` executa a remocao definitiva.

## Operacao manual

```bash
sudo ./mind_sanitize_users.sh --csv usuarios.csv --dry-run
sudo ./mind_sanitize_users.sh --csv usuarios.csv --apply
```

## Operacao com planner

```bash
sudo ./mind_sanitize_users.sh --plan-json /var/log/mind/mind_access_sync_*.json --apply
sudo ./mind_sanitize_users.sh --process-retention --apply
```

## Evidencias

Os relatórios sao gravados em `/var/log/mind/`:

- TXT para leitura humana;
- JSON para auditoria e consumo por automacao;
- estado persistente em `/var/lib/mind/mind_sanitize_users_state.json`.

## Cuidados

- contas protegidas nao devem ser alteradas;
- a execucao real exige `root`;
- entradas invalidas devem ser rejeitadas antes da aplicacao;
- rotinas automaticas precisam de fonte de entrada valida.

## Relacao com o projeto

Este modulo complementa a governanca de acessos. O planner de acessos define
quem deve ser mantido, criado ou removido; o sanitizador executa o bloqueio, a
remocao e a retencao conforme a politica operacional.

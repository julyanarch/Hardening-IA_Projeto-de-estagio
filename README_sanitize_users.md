# MIND User Sanitizer

Este documento explica somente o funcionamento do script `mind_sanitize_users.sh`.

O objetivo dele é ler um arquivo CSV com usuários que precisam ser bloqueados ou removidos de um servidor Linux, normalmente a partir de um chamado interno de desligamento ou remoção de acesso.

O script gera evidências em texto e JSON para auditoria e para alimentar a IA interna.

## Arquivo principal

```bash
mind_sanitize_users.sh
```

## O que o script faz

O script lê um CSV linha por linha e executa uma ação para cada usuário.

Ele suporta três ações:

- `lock`: bloqueia o usuário, mas não remove a conta
- `remove`: remove o usuário, podendo manter ou apagar a home
- `purge`: remove o usuário e apaga a home

Por segurança, ele possui dois modos:

- `--dry-run`: apenas simula o que seria feito
- `--apply`: executa de verdade no servidor

Sempre rode primeiro com `--dry-run`.

## Formato do CSV

O CSV precisa ter este cabeçalho:

```csv
username,action,remove_home,reason,ticket
```

Exemplo:

```csv
username,action,remove_home,reason,ticket
usuario_teste,remove,yes,desligamento,CHG0001
```

Cada campo significa:

- `username`: nome do usuário Linux que será tratado
- `action`: ação desejada, podendo ser `lock`, `remove` ou `purge`
- `remove_home`: use `yes` para apagar a home junto com o usuário, ou `no` para manter
- `reason`: motivo da ação
- `ticket`: número do chamado interno

Importante: não use vírgula dentro dos campos.

Errado:

```csv
usuario_teste,remove,yes,desligamento, urgente,CHG0001
```

Certo:

```csv
usuario_teste,remove,yes,desligamento urgente,CHG0001
```

## Como criar um usuário de teste

Antes de testar a remoção, crie um usuário fake no servidor Linux:

```bash
sudo useradd -m usuario_teste
```

Confira se ele foi criado:

```bash
getent passwd usuario_teste
```

Se aparecer uma linha parecida com esta, o usuário existe:

```text
usuario_teste:x:1001:1001::/home/usuario_teste:/bin/sh
```

Confira também a home:

```bash
ls -ld /home/usuario_teste
```

## Como criar o CSV usando nano

No servidor Linux, crie o arquivo:

```bash
nano usuarios.csv
```

Dentro do `nano`, escreva:

```csv
username,action,remove_home,reason,ticket
usuario_teste,remove,yes,desligamento,CHG0001
```

Depois salve o arquivo:

1. Pressione `Ctrl + O`
2. Pressione `Enter`
3. Pressione `Ctrl + X`

## Como rodar em modo simulação

Primeiro dê permissão de execução ao script:

```bash
chmod +x mind_sanitize_users.sh
```

Rode em modo simulação:

```bash
sudo ./mind_sanitize_users.sh --csv usuarios.csv --dry-run
```

Nesse modo o script não remove nada. Ele só mostra o que faria.

Exemplo esperado:

```text
[ALERTA] Modo DRY-RUN: nenhuma alteracao real sera executada.
[INFO] Removendo usuario: usuario_teste
[INFO] DRY-RUN: userdel -r usuario_teste
[OK] usuario_teste: usuario removido com home
```

Depois da simulação, o usuário ainda deve existir:

```bash
getent passwd usuario_teste
```

## Como remover o usuário de verdade

Se o `--dry-run` estiver correto, execute:

```bash
sudo ./mind_sanitize_users.sh --csv usuarios.csv --apply
```

Esse comando executa a remoção real.

Para confirmar que o usuário foi removido:

```bash
getent passwd usuario_teste
```

Se não aparecer nada, o usuário foi removido.

Para confirmar que a home foi apagada:

```bash
ls -ld /home/usuario_teste
```

Se aparecer algo como `No such file or directory`, a home também foi removida.

## Exemplos de uso

### Bloquear usuário sem remover

CSV:

```csv
username,action,remove_home,reason,ticket
usuario_teste,lock,no,afastamento,CHG0002
```

Comando:

```bash
sudo ./mind_sanitize_users.sh --csv usuarios.csv --apply
```

### Remover usuário mantendo a home

CSV:

```csv
username,action,remove_home,reason,ticket
usuario_teste,remove,no,desligamento,CHG0003
```

Comando:

```bash
sudo ./mind_sanitize_users.sh --csv usuarios.csv --apply
```

### Remover usuário apagando a home

CSV:

```csv
username,action,remove_home,reason,ticket
usuario_teste,remove,yes,desligamento,CHG0004
```

Comando:

```bash
sudo ./mind_sanitize_users.sh --csv usuarios.csv --apply
```

### Remover usuário e home usando purge

CSV:

```csv
username,action,remove_home,reason,ticket
usuario_teste,purge,yes,desligamento,CHG0005
```

Comando:

```bash
sudo ./mind_sanitize_users.sh --csv usuarios.csv --apply
```

## Onde ficam os relatórios

O script salva evidências em:

```bash
/var/log/mind/
```

Arquivos gerados:

```text
mind_sanitize_users_HOST_DATA.txt
mind_sanitize_users_HOST_DATA.json
```

O `.txt` serve para leitura humana.

O `.json` serve para auditoria, automação e consumo pela IA interna.

## Segurança

O script bloqueia alterações em usuários críticos, como:

```text
root daemon bin sys nobody www-data sshd
```

Se algum desses usuários aparecer no CSV, o script não executa a alteração e registra como bloqueado.

## Fluxo recomendado

1. Criar ou receber o CSV do chamado interno
2. Conferir se o usuário existe com `getent passwd usuario`
3. Rodar `--dry-run`
4. Validar a saída na tela
5. Rodar `--apply`
6. Conferir se o usuário foi removido ou bloqueado
7. Guardar o TXT/JSON gerado em `/var/log/mind`


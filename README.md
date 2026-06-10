# MIND Access Governance

O projeto agora tem foco exclusivo em controle de acessos via planilha Excel
Online / SharePoint.

A planilha funciona como fonte central da verdade. O script
`mind_access_sync.py` lê o workbook `.xlsx`, normaliza os nomes para logins Linux
e gera um plano de sincronização em TXT e JSON.

## Fluxo Atual

```text
Planilha Excel Online
        |
        v
mind_access_sync.py
        |
        v
Normalizacao de usuarios Linux
        |
        v
Comparacao com o estado do servidor
        |
        v
Plano de criacao / manutencao / remocao
        |
        v
TXT + JSON para auditoria e automacao
```

## Arquivos Principais

| Arquivo | Funcao |
| --- | --- |
| `mind_access_sync.py` | Le a planilha e gera o plano de sincronizacao |
| `acessos_exemplo.xlsx` | Planilha exemplo com os nomes solicitados |
| `README_acesso_excel.md` | Documentacao detalhada da nova proposta |

## Planilha Exemplo

O repositório terá uma planilha base com estes nomes:

- João Paulo Araujo
- Douglas Michel Da Silva
- Julyana Silva da Rocha
- Odair Batista Gonçalves dos Santos
- Carlos Roitman Amaral Maceno

O arquivo exemplo pode ser recriado a qualquer momento com:

```bash
python3 mind_access_sync.py --create-template --template-path acessos_exemplo.xlsx
```

## Como Usar

Gerar o plano a partir da planilha:

```bash
python3 mind_access_sync.py --workbook acessos_exemplo.xlsx --sheet Acessos
```

## Estrutura

```text
.
├── mind_access_sync.py
├── acessos_exemplo.xlsx
├── README.md
├── README_acesso_excel.md
└── .gitignore
```

## Proximos Passos

1. Levar essa planilha para o SharePoint.
2. Definir quem pode editar e auditar o workbook.
3. Ligar a saida do `mind_access_sync.py` a uma automacao futura.

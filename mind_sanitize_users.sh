#!/usr/bin/env bash
set -Eeuo pipefail

# ------------------------------------------------------------
# MIND • Linux User Sanitizer
# Objetivo: executar offboarding/sanitização de usuários Linux
# Entrada: CSV exportado do chamado interno
# Saída: relatório .txt + .json para auditoria e IA interna (MIND)
# ------------------------------------------------------------

APP="mind_sanitize_users"
OUT_DIR="/var/log/mind"
HOST="$(hostname -s 2>/dev/null || hostname)"
STAMP="$(date +'%Y%m%d_%H%M%S')"
TXT="${OUT_DIR}/${APP}_${HOST}_${STAMP}.txt"
JSON="${OUT_DIR}/${APP}_${HOST}_${STAMP}.json"

CSV_FILE=""
APPLY="false"

PROTECTED_USERS="root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve messagebus sshd"

mkdir -p "$OUT_DIR"
chmod 0750 "$OUT_DIR" 2>/dev/null || true

exec > >(tee -a "$TXT") 2>&1

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
CYAN="\e[36m"
BOLD="\e[1m"
RESET="\e[0m"

ok()    { echo -e "${GREEN}[OK]${RESET} $*" >&2; }
warn()  { echo -e "${YELLOW}[ALERTA]${RESET} $*" >&2; }
crit()  { echo -e "${RED}[CRITICO]${RESET} $*" >&2; }
info()  { echo -e "${BLUE}[INFO]${RESET} $*" >&2; }

section() {
  echo >&2
  echo -e "${CYAN}${BOLD}========================================================${RESET}" >&2
  echo -e "${CYAN}${BOLD}$1${RESET}" >&2
  echo -e "${CYAN}${BOLD}========================================================${RESET}" >&2
}

usage() {
  cat <<EOF
Uso:
  sudo ./mind_sanitize_users.sh --csv usuarios.csv --dry-run
  sudo ./mind_sanitize_users.sh --csv usuarios.csv --apply

Formato esperado do CSV:
  username,action,remove_home,reason,ticket
  joao.silva,remove,yes,desligamento,CHG12345
  maria.souza,lock,no,afastamento,CHG12346

Acoes suportadas:
  lock    Bloqueia a conta com usermod -L e expira o acesso.
  remove  Remove o usuario, mantendo a home por padrao.
  purge   Remove o usuario e a home, equivalente a remove_home=yes.

Observacoes:
  --dry-run e o comportamento seguro para simular a execucao.
  --apply executa alteracoes reais no servidor.
EOF
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  value="${value%$'\r'}"
  echo "$value"
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/}"
  echo "$value"
}

is_protected_user() {
  local username="$1"
  for protected in $PROTECTED_USERS; do
    [[ "$username" == "$protected" ]] && return 0
  done
  return 1
}

valid_username() {
  local username="$1"
  [[ "$username" =~ ^[a-z_][a-z0-9_.-]*[$]?$ ]]
}

have_user() {
  local username="$1"
  getent passwd "$username" >/dev/null 2>&1
}

run_or_preview() {
  if [[ "$APPLY" == "true" ]]; then
    "$@"
  else
    info "DRY-RUN: $*"
  fi
}

emit_json() {
  local json_items="$1"

  {
    echo "{"
    echo "  \"meta\": {"
    echo "    \"tool\": \"mind_sanitize_users\","
    echo "    \"generated_at\": \"$(date -Is)\","
    echo "    \"host\": \"$(json_escape "$HOST")\","
    echo "    \"mode\": \"$([[ "$APPLY" == "true" ]] && echo "apply" || echo "dry-run")\","
    echo "    \"source_csv\": \"$(json_escape "$CSV_FILE")\""
    echo "  },"
    echo "  \"results\": ["
    printf "%s\n" "$json_items"
    echo "  ]"
    echo "}"
  } > "$JSON"

  chmod 0640 "$JSON" 2>/dev/null || true
  ok "JSON gerado: $JSON"
}

append_json_item() {
  local current="$1"
  local username="$2"
  local action="$3"
  local remove_home="$4"
  local status="$5"
  local reason="$6"
  local ticket="$7"
  local message="$8"
  local comma=""

  [[ -n "$current" ]] && comma=","

  cat <<EOF
${current}${comma}
    {
      "username": "$(json_escape "$username")",
      "action": "$(json_escape "$action")",
      "remove_home": "$(json_escape "$remove_home")",
      "status": "$(json_escape "$status")",
      "reason": "$(json_escape "$reason")",
      "ticket": "$(json_escape "$ticket")",
      "message": "$(json_escape "$message")"
    }
EOF
}

parse_args() {
  if [[ "$#" -eq 0 ]]; then
    usage
    exit 1
  fi

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --csv)
        CSV_FILE="${2:-}"
        shift 2
        ;;
      --apply)
        APPLY="true"
        shift
        ;;
      --dry-run)
        APPLY="false"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        crit "Argumento invalido: $1"
        usage
        exit 1
        ;;
    esac
  done

  if [[ -z "$CSV_FILE" ]]; then
    crit "Informe o arquivo CSV com --csv."
    exit 1
  fi

  if [[ ! -r "$CSV_FILE" ]]; then
    crit "CSV nao encontrado ou sem permissao de leitura: $CSV_FILE"
    exit 2
  fi

  if [[ "$APPLY" == "true" && "${EUID:-$(id -u)}" -ne 0 ]]; then
    crit "Use sudo para executar em modo --apply."
    exit 3
  fi
}

process_row() {
  local username="$1"
  local action="$2"
  local remove_home="$3"
  local reason="$4"
  local ticket="$5"
  local status="ok"
  local message=""

  username="$(trim "$username")"
  action="$(trim "$action")"
  remove_home="$(trim "$remove_home")"
  reason="$(trim "$reason")"
  ticket="$(trim "$ticket")"

  action="${action,,}"
  remove_home="${remove_home,,}"

  if [[ -z "$username" ]]; then
    echo "skipped|username vazio"
    return 0
  fi

  if [[ "$username" == "username" ]]; then
    echo "header|cabecalho ignorado"
    return 0
  fi

  if ! valid_username "$username"; then
    echo "failed|username invalido"
    return 0
  fi

  if is_protected_user "$username"; then
    echo "blocked|usuario protegido nao pode ser alterado"
    return 0
  fi

  if ! have_user "$username"; then
    echo "skipped|usuario nao existe no servidor"
    return 0
  fi

  case "$action" in
    lock)
      info "Bloqueando usuario: $username"
      if run_or_preview usermod -L "$username" && run_or_preview chage -E 0 "$username"; then
        message="usuario bloqueado e expirado"
      else
        status="failed"
        message="falha ao bloquear ou expirar usuario"
      fi
      ;;
    remove|delete)
      info "Removendo usuario: $username"
      if [[ "$remove_home" == "yes" || "$remove_home" == "true" || "$remove_home" == "1" ]]; then
        if run_or_preview userdel -r "$username"; then
          message="usuario removido com home"
        else
          status="failed"
          message="falha ao remover usuario com home"
        fi
      else
        if run_or_preview userdel "$username"; then
          message="usuario removido mantendo home"
        else
          status="failed"
          message="falha ao remover usuario mantendo home"
        fi
      fi
      ;;
    purge)
      info "Removendo usuario e home: $username"
      if run_or_preview userdel -r "$username"; then
        message="usuario removido com home"
      else
        status="failed"
        message="falha ao remover usuario com home"
      fi
      ;;
    *)
      status="failed"
      message="acao invalida: $action"
      ;;
  esac

  echo "${status}|${message}"
}

main() {
  parse_args "$@"

  section "MIND USER SANITIZER - Inicio"
  info "Host       : $HOST"
  info "CSV        : $CSV_FILE"
  info "Relatorio  : $TXT"
  info "JSON       : $JSON"

  if [[ "$APPLY" == "true" ]]; then
    warn "Modo APPLY: alteracoes reais serao executadas."
  else
    warn "Modo DRY-RUN: nenhuma alteracao real sera executada."
  fi

  local json_items=""
  local total=0 ok_count=0 skipped_count=0 failed_count=0 blocked_count=0

  section "Processamento do CSV"
  while IFS=',' read -r username action remove_home reason ticket extra || [[ -n "${username:-}" ]]; do
    total=$((total + 1))
    local result status message
    result="$(process_row "${username:-}" "${action:-}" "${remove_home:-}" "${reason:-}" "${ticket:-}")"
    status="${result%%|*}"
    message="${result#*|}"

    if [[ "$status" == "header" ]]; then
      total=$((total - 1))
      continue
    fi

    case "$status" in
      ok)
        ok_count=$((ok_count + 1))
        ok "${username}: $message"
        ;;
      skipped)
        skipped_count=$((skipped_count + 1))
        warn "${username}: $message"
        ;;
      blocked)
        blocked_count=$((blocked_count + 1))
        crit "${username}: $message"
        ;;
      failed)
        failed_count=$((failed_count + 1))
        crit "${username}: $message"
        ;;
    esac

    json_items="$(append_json_item "$json_items" "${username:-}" "${action:-}" "${remove_home:-}" "${status:-}" "${reason:-}" "${ticket:-}" "${message:-}")"
  done < "$CSV_FILE"

  section "Resumo"
  info "Total processado : $total"
  ok   "Sucesso          : $ok_count"
  warn "Ignorados        : $skipped_count"
  crit "Bloqueados       : $blocked_count"
  crit "Falhas           : $failed_count"

  emit_json "$json_items"

  section "MIND USER SANITIZER - Fim"
}

main "$@"

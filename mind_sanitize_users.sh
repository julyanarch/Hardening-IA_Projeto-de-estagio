#!/usr/bin/env bash
set -Eeuo pipefail

# ------------------------------------------------------------
# MIND • Linux User Sanitizer
# Objetivo: executar offboarding/sanitizacao de usuarios Linux
# Entrada: CSV legado ou JSON do plano gerado pela planilha
# Saida: relatorio .txt + .json para auditoria e IA interna (MIND)
# ------------------------------------------------------------

APP="mind_sanitize_users"
OUT_DIR="/var/log/mind"
STATE_DIR="/var/lib/mind"
HOST="$(hostname -s 2>/dev/null || hostname)"
STAMP="$(date +'%Y%m%d_%H%M%S')"
TXT="${OUT_DIR}/${APP}_${HOST}_${STAMP}.txt"
JSON="${OUT_DIR}/${APP}_${HOST}_${STAMP}.json"
STATE_FILE="${STATE_DIR}/mind_sanitize_users_state.json"

CSV_FILE=""
PLAN_JSON=""
APPLY="false"
PROCESS_RETENTION="false"
RETENTION_DAYS="90"

PROTECTED_USERS="root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve messagebus sshd"

mkdir -p "$OUT_DIR" "$STATE_DIR"
chmod 0750 "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true

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
  sudo ./mind_sanitize_users.sh --plan-json mind_access_sync.json --apply
  sudo ./mind_sanitize_users.sh --process-retention --apply

Formato legado do CSV:
  username,action,remove_home,reason,ticket
  joao.silva,remove,yes,desligamento,CHG12345
  maria.souza,lock,no,afastamento,CHG12346

Acoes suportadas:
  lock    Bloqueia a conta com usermod -L e expira o acesso.
  remove  Remove o usuario, mantendo a home por padrao.
  purge   Remove o usuario e a home, equivalente a remove_home=yes.

Novos modos:
  --plan-json consome o diff da planilha e bloqueia usuarios removidos.
  --process-retention aplica a regra de 90 dias para usuarios bloqueados.

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

ensure_root_apply() {
  if [[ "$APPLY" == "true" && "${EUID:-$(id -u)}" -ne 0 ]]; then
    crit "Use sudo para executar em modo --apply."
    exit 3
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
    echo "    \"source_csv\": \"$(json_escape "$CSV_FILE")\","
    echo "    \"source_plan_json\": \"$(json_escape "$PLAN_JSON")\","
    echo "    \"state_file\": \"$(json_escape "$STATE_FILE")\","
    echo "    \"retention_days\": $RETENTION_DAYS"
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

load_plan_json() {
  local path="$1"
  python3 - "$path" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
for item in data.get("diff", {}).get("to_remove", []):
    item = str(item).strip()
    if item:
        print(item)
PY
}

state_init() {
  if [[ -f "$STATE_FILE" ]]; then
    return 0
  fi

  cat > "$STATE_FILE" <<EOF
{
  "meta": {
    "tool": "mind_sanitize_users",
    "created_at": "$(date -Is)",
    "host": "$(json_escape "$HOST")"
  },
  "blocked_users": {}
}
EOF
  chmod 0640 "$STATE_FILE" 2>/dev/null || true
}

state_set_blocked() {
  local username="$1"
  local blocked_at="$2"
  local source_plan="$3"
  local ticket="$4"
  local reason="$5"

  python3 - "$STATE_FILE" "$username" "$blocked_at" "$source_plan" "$ticket" "$reason" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
username = sys.argv[2]
blocked_at = sys.argv[3]
source_plan = sys.argv[4]
ticket = sys.argv[5]
reason = sys.argv[6]

data = json.loads(path.read_text(encoding="utf-8"))
blocked = data.setdefault("blocked_users", {})
blocked[username] = {
    "blocked_at": blocked_at,
    "source_plan": source_plan,
    "ticket": ticket,
    "reason": reason,
    "status": "blocked",
}
path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
PY
}

state_get_blocked_at() {
  local username="$1"
  python3 - "$STATE_FILE" "$username" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
username = sys.argv[2]
if not path.exists():
    raise SystemExit(0)
data = json.loads(path.read_text(encoding="utf-8"))
entry = data.get("blocked_users", {}).get(username, {})
print(entry.get("blocked_at", ""))
PY
}

state_remove_user() {
  local username="$1"
  python3 - "$STATE_FILE" "$username" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
username = sys.argv[2]
if not path.exists():
    raise SystemExit(0)
data = json.loads(path.read_text(encoding="utf-8"))
data.setdefault("blocked_users", {}).pop(username, None)
path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
PY
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
    if [[ "$APPLY" == "true" ]]; then
      state_remove_user "$username"
    fi
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

process_plan_block() {
  local username="$1"
  local source_plan="$2"
  local ticket="$3"
  local reason="$4"
  local status="ok"
  local message=""
  local blocked_at=""

  username="$(trim "$username")"
  source_plan="$(trim "$source_plan")"
  ticket="$(trim "$ticket")"
  reason="$(trim "$reason")"

  if [[ -z "$username" ]]; then
    echo "skipped|username vazio"
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
    if [[ "$APPLY" == "true" ]]; then
      state_remove_user "$username"
    fi
    echo "skipped|usuario nao existe no servidor"
    return 0
  fi

  blocked_at="$(state_get_blocked_at "$username")"
  if [[ -z "$blocked_at" ]]; then
    blocked_at="$(date -Is)"
    info "Bloqueando usuario removido da planilha: $username"
    if run_or_preview usermod -L "$username" && run_or_preview chage -E 0 "$username"; then
      message="usuario bloqueado por remocao da planilha"
      if [[ "$APPLY" == "true" ]]; then
        state_set_blocked "$username" "$blocked_at" "$source_plan" "$ticket" "$reason"
      fi
    else
      status="failed"
      message="falha ao bloquear usuario removido da planilha"
    fi
  else
    info "Usuario ja esta bloqueado na retencao: $username"
    message="usuario ja bloqueado anteriormente"
  fi

  echo "${status}|${message}"
}

process_csv_mode() {
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
}

process_plan_json_mode() {
  state_init
  local json_items=""
  local total=0 ok_count=0 skipped_count=0 failed_count=0 blocked_count=0
  local source_plan
  source_plan="$(basename "$PLAN_JSON")"

  section "Processamento do JSON da planilha"
  info "Plano      : $PLAN_JSON"
  info "Estado     : $STATE_FILE"
  info "Retencao   : ${RETENTION_DAYS} dias"

  while IFS= read -r username; do
    [[ -z "$username" ]] && continue
    total=$((total + 1))
    local result status message
    result="$(process_plan_block "$username" "$source_plan" "" "usuario removido da planilha")"
    status="${result%%|*}"
    message="${result#*|}"

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

    json_items="$(append_json_item "$json_items" "${username:-}" "plan-json" "n/a" "${status:-}" "usuario removido da planilha" "" "${message:-}")"
  done < <(load_plan_json "$PLAN_JSON")

  section "Resumo JSON"
  info "Total processado : $total"
  ok   "Sucesso          : $ok_count"
  warn "Ignorados        : $skipped_count"
  crit "Bloqueados       : $blocked_count"
  crit "Falhas           : $failed_count"

  emit_json "$json_items"
}

process_retention_mode() {
  state_init
  local now_epoch
  now_epoch="$(date +%s)"
  local json_items=""
  local total=0 ok_count=0 skipped_count=0 failed_count=0 blocked_count=0

  while IFS= read -r username; do
    [[ -z "$username" ]] && continue
    local blocked_at blocked_epoch age_seconds result status message
    blocked_at="$(state_get_blocked_at "$username")"
    [[ -z "$blocked_at" ]] && continue

    blocked_epoch="$(date -d "$blocked_at" +%s 2>/dev/null || echo 0)"
    [[ "$blocked_epoch" -eq 0 ]] && continue

    age_seconds=$((now_epoch - blocked_epoch))
    if [[ "$age_seconds" -ge $((RETENTION_DAYS * 86400)) ]]; then
      total=$((total + 1))
      info "Purgando usuario com mais de ${RETENTION_DAYS} dias: $username"
      if run_or_preview userdel -r "$username"; then
        status="ok"
        message="usuario removido apos retencao"
        if [[ "$APPLY" == "true" ]]; then
          state_remove_user "$username"
        fi
      else
        status="failed"
        message="falha ao remover usuario apos retencao"
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

      json_items="$(append_json_item "$json_items" "${username:-}" "retention-purge" "n/a" "${status:-}" "retencao de ${RETENTION_DAYS} dias" "" "${message:-}")"
    fi
  done < <(python3 - "$STATE_FILE" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit(0)
data = json.loads(path.read_text(encoding="utf-8"))
for username in sorted(data.get("blocked_users", {}).keys()):
    print(username)
PY
  )

  if [[ -n "$json_items" ]]; then
    emit_json "$json_items"
  fi
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
      --plan-json)
        PLAN_JSON="${2:-}"
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
      --process-retention)
        PROCESS_RETENTION="true"
        shift
        ;;
      --retention-days)
        RETENTION_DAYS="${2:-90}"
        shift 2
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

  if [[ -n "$CSV_FILE" && -n "$PLAN_JSON" ]]; then
    crit "Use somente um modo de entrada por vez: CSV ou JSON."
    exit 1
  fi

  if [[ -n "$CSV_FILE" && "$PROCESS_RETENTION" == "true" ]]; then
    crit "O modo de retencao nao usa CSV."
    exit 1
  fi

  if [[ -n "$PLAN_JSON" && "$PROCESS_RETENTION" == "true" ]]; then
    crit "Use apenas --plan-json ou --process-retention."
    exit 1
  fi

  if [[ -z "$CSV_FILE" && -z "$PLAN_JSON" && "$PROCESS_RETENTION" != "true" ]]; then
    crit "Informe --csv, --plan-json ou --process-retention."
    exit 1
  fi

  if [[ -n "$CSV_FILE" && ! -r "$CSV_FILE" ]]; then
    crit "CSV nao encontrado ou sem permissao de leitura: $CSV_FILE"
    exit 2
  fi

  if [[ -n "$PLAN_JSON" && ! -r "$PLAN_JSON" ]]; then
    crit "JSON nao encontrado ou sem permissao de leitura: $PLAN_JSON"
    exit 2
  fi

  ensure_root_apply
}

main() {
  parse_args "$@"

  section "MIND USER SANITIZER - Inicio"
  info "Host       : $HOST"
  info "Relatorio  : $TXT"
  info "JSON       : $JSON"
  info "State file  : $STATE_FILE"
  info "Retencao   : ${RETENTION_DAYS} dias"

  if [[ "$APPLY" == "true" ]]; then
    warn "Modo APPLY: alteracoes reais serao executadas."
  else
    warn "Modo DRY-RUN: nenhuma alteracao real sera executada."
  fi

  if [[ -n "$CSV_FILE" ]]; then
    info "Modo       : csv"
    process_csv_mode
  elif [[ -n "$PLAN_JSON" ]]; then
    info "Modo       : plan-json"
    process_plan_json_mode
  else
    info "Modo       : retention"
    section "Processamento de retencao"
    process_retention_mode
  fi

  section "MIND USER SANITIZER - Fim"
}

main "$@"

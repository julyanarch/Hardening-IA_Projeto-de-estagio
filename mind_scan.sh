#!/usr/bin/env bash
set -Eeuo pipefail

# ------------------------------------------------------------
# MIND • Linux Quick Risk Scan (Sensor)
# Objetivo: varredura leve de "deslizes" operacionais e segurança
# Saída: relatório .txt + .json para alimentar a IA interna (MIND)
# ------------------------------------------------------------

APP="mind_scan"
OUT_DIR="/var/log/mind"
STATE_DIR="/var/lib/mind"

HOST="$(hostname -s 2>/dev/null || hostname)"
STAMP="$(date +'%Y%m%d_%H%M%S')"
TXT="${OUT_DIR}/${APP}_${HOST}_${STAMP}.txt"
JSON="${OUT_DIR}/${APP}_${HOST}_${STAMP}.json"
BASELINE="${STATE_DIR}/baseline_${HOST}.json"

mkdir -p "$OUT_DIR" "$STATE_DIR"
chmod 0750 "$OUT_DIR" "$STATE_DIR" 2>/dev/null || true

# Log unificado (tela + arquivo)
exec > >(tee -a "$TXT") 2>&1

# --------- Cores ----------
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
CYAN="\e[36m"
BOLD="\e[1m"
RESET="\e[0m"

ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[ALERTA]${RESET} $*"; }
crit()  { echo -e "${RED}[CRÍTICO]${RESET} $*"; }
info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }

# --------- Estilo de seção ----------
section() {
  echo
  echo -e "${CYAN}${BOLD}┌────────────────────────────────────────────────────────${RESET}"
  echo -e "${CYAN}${BOLD}│ $1${RESET}"
  echo -e "${CYAN}${BOLD}└────────────────────────────────────────────────────────${RESET}"
}

have() { command -v "$1" >/dev/null 2>&1; }

# --------- Coletas ----------
collect_system() {
  section "SISTEMA (host, uptime, OS, kernel, CPU/RAM)"
  local now os kernel uptime_h loadavg mem

  now="$(date -Is)"
  os="$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"')"
  kernel="$(uname -r 2>/dev/null || true)"
  uptime_h="$(awk '{print int($1/3600)}' /proc/uptime 2>/dev/null || echo 0)"
  loadavg="$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo 'N/A')"
  mem="$(free -m 2>/dev/null || true)"

  info "Timestamp : $now"
  info "Hostname  : $HOST"
  info "OS        : ${os:-N/A}"
  info "Kernel    : ${kernel:-N/A}"
  info "Uptime(h) : ${uptime_h}"
  info "Loadavg   : ${loadavg}"
  echo
  echo -e "${BOLD}Memória (MB):${RESET}"
  echo "$mem"
  echo
  echo -e "${BOLD}Top CPU (processos):${RESET}"
  ps -eo pid,comm,%cpu --sort=-%cpu 2>/dev/null | head -n 8 || true
}

collect_inodes() {
  section "FILESYSTEM • INODES (arquivos pequenos enchendo inode)"
  if have df; then
    df -i 2>/dev/null || true
    echo
    warn "Dica: inode alto (ex.: >90%) pode travar o sistema mesmo com espaço livre."
  else
    crit "df não encontrado."
  fi
}

collect_disk_usage() {
  section "FILESYSTEM • Uso de disco"
  if have df; then
    df -hPT 2>/dev/null || true
    echo
    warn "Dica: volumes acima de 85% merecem acompanhamento; acima de 90% indicam risco operacional."
  else
    crit "df não encontrado."
  fi
}

collect_security_uid0() {
  section "SEGURANÇA • Usuários com UID 0"
  local list
  list="$(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null || true)"

  if [[ -z "$list" ]]; then
    warn "Não foi possível listar UID 0."
    return 0
  fi

  echo "$list" | while read -r u; do
    [[ -z "$u" ]] && continue
    if [[ "$u" == "root" ]]; then
      ok "UID0: $u"
    else
      crit "UID0 adicional: $u"
    fi
  done
}

collect_security_privileged_users() {
  section "SEGURANÇA • Usuários com privilégios elevados"

  if have getent; then
    local sudo_group wheel_group
    sudo_group="$(getent group sudo 2>/dev/null | cut -d: -f4 || true)"
    wheel_group="$(getent group wheel 2>/dev/null | cut -d: -f4 || true)"

    info "Grupo sudo : ${sudo_group:-<vazio/ausente>}"
    info "Grupo wheel: ${wheel_group:-<vazio/ausente>}"
  else
    warn "getent não encontrado para listar grupos privilegiados."
  fi

  if [[ -r /etc/sudoers ]]; then
    echo
    info "Regras ativas em /etc/sudoers (amostra):"
    grep -Ev '^\s*#|^\s*$' /etc/sudoers 2>/dev/null | head -n 20 || true
  fi
}

collect_security_ssh() {
  section "SEGURANÇA • SSH (root login e senha)"
  local sshd="/etc/ssh/sshd_config"
  local prl pwa

  prl="$(awk 'tolower($1)=="permitrootlogin"{print tolower($2)}' "$sshd" 2>/dev/null | tail -n1 || true)"
  pwa="$(awk 'tolower($1)=="passwordauthentication"{print tolower($2)}' "$sshd" 2>/dev/null | tail -n1 || true)"

  info "Arquivo: $sshd"

  if [[ "${prl:-}" == "yes" || -z "${prl:-}" ]]; then
    crit "PermitRootLogin        : ${prl:-<default/ausente>}"
  else
    ok   "PermitRootLogin        : ${prl:-<default/ausente>}"
  fi

  if [[ "${pwa:-}" == "yes" || -z "${pwa:-}" ]]; then
    warn "PasswordAuthentication : ${pwa:-<default/ausente>}"
  else
    ok   "PasswordAuthentication : ${pwa:-<default/ausente>}"
  fi
}

collect_security_ports() {
  section "SEGURANÇA • Portas/serviços em escuta"
  if have ss; then
    ss -tunap 2>/dev/null | sed -n '1,120p' || true
  elif have netstat; then
    netstat -tulpn 2>/dev/null | sed -n '1,120p' || true
  else
    warn "ss/netstat não encontrado."
  fi
}

collect_security_world_writable() {
  section "SEGURANÇA • Arquivos world-writable (escrita para 'others')"
  info "Amostra (até 200) — ignorando /proc /sys /dev:"
  find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -path /dev -prune -o \
    -type f -perm -0002 -print 2>/dev/null | head -n 200 || true
}

sha_file() {
  local f="$1"
  if [[ -r "$f" ]]; then
    sha256sum "$f" 2>/dev/null | awk '{print $1}' || true
  else
    echo ""
  fi
}

collect_security_integrity() {
  section "SEGURANÇA • Integridade (/etc/passwd e /etc/shadow)"
  local p_hash s_hash old_p old_s

  p_hash="$(sha_file /etc/passwd)"
  s_hash="$(sha_file /etc/shadow)"

  info "sha256(/etc/passwd) : ${p_hash:-N/A}"
  info "sha256(/etc/shadow) : ${s_hash:-N/A}"

  if [[ -f "$BASELINE" ]]; then
    old_p="$(python3 -c "import json;print(json.load(open('$BASELINE'))['etc_passwd_sha256'])" 2>/dev/null || true)"
    old_s="$(python3 -c "import json;print(json.load(open('$BASELINE'))['etc_shadow_sha256'])" 2>/dev/null || true)"
    ok "Baseline encontrado  : $BASELINE"

    if [[ "$p_hash" == "$old_p" ]]; then
      ok "Mudança /etc/passwd  : não"
    else
      crit "Mudança /etc/passwd  : SIM"
    fi

    if [[ "$s_hash" == "$old_s" ]]; then
      ok "Mudança /etc/shadow  : não"
    else
      crit "Mudança /etc/shadow  : SIM"
    fi
  else
    warn "Baseline inexistente : será criado ao final."
  fi
}

collect_firewall() {
  section "SEGURANÇA • Firewall (ufw/iptables)"
  if have ufw; then
    local st
    st="$(ufw status 2>/dev/null | head -n 1 || true)"
    echo "$st"
    if echo "$st" | grep -qi "active"; then
      ok "UFW ativo."
    else
      warn "UFW parece inativo."
    fi
  elif have iptables; then
    info "iptables (resumo):"
    iptables -S 2>/dev/null | head -n 30 || true
    warn "Valide se existem regras corporativas aplicadas."
  else
    warn "Nenhum ufw/iptables detectado."
  fi
}

collect_services_failed() {
  section "SERVIÇOS • systemd failed"
  if have systemctl; then
    systemctl --failed --no-pager 2>/dev/null || true
  else
    warn "systemctl não encontrado."
  fi
}

collect_logs_keywords() {
  section "LOGS • Palavras-chave (error/failed/critical)"
  for f in /var/log/syslog /var/log/auth.log; do
    if [[ -r "$f" ]]; then
      info "-- $f (últimas 20 ocorrências) --"
      local out
      out="$(grep -iE "error|failed|critical" "$f" 2>/dev/null | tail -n 20 || true)"
      [[ -n "$out" ]] && echo "$out" || ok "(nenhuma ocorrência recente encontrada na amostra)"
      echo
    fi
  done
}

collect_updates_repos() {
  section "PATCHING • Updates pendentes + Repositórios (autorização)"
  if have apt-get; then
    local pending
    pending="$(apt-get -s upgrade 2>/dev/null | awk '/^Inst /{c++} END{print c+0}')"
    info "Gerenciador: apt"
    warn "Updates pendentes (estimativa): ${pending:-0}"
    echo
    info "Repositórios (sources.list / sources.list.d):"
    [[ -r /etc/apt/sources.list ]] && sed -n '1,120p' /etc/apt/sources.list || true
    if [[ -d /etc/apt/sources.list.d ]]; then
      echo
      info "Arquivos em sources.list.d:"
      ls -1 /etc/apt/sources.list.d 2>/dev/null | sed 's/^/ - /' || true
    fi
  elif have yum; then
    info "Gerenciador: yum"
    yum check-update -q 2>/dev/null | sed -n '1,80p' || true
  elif have dnf; then
    info "Gerenciador: dnf"
    dnf check-update -q 2>/dev/null | sed -n '1,80p' || true
  else
    warn "Gerenciador de pacotes não detectado."
  fi

  echo
  info "Nota prática: para 'repos não autorizados', a empresa define uma whitelist."
  info "Ex.: validar se o dominio do repo pertence ao padrão corporativo."
}

make_baseline_if_needed() {
  section "STATE • Baseline de integridade"
  local now p_hash s_hash
  now="$(date -Is)"
  p_hash="$(sha_file /etc/passwd)"
  s_hash="$(sha_file /etc/shadow)"

  if [[ ! -f "$BASELINE" ]]; then
    cat > "$BASELINE" <<EOF
{
  "created_at": "$now",
  "etc_passwd_sha256": "$p_hash",
  "etc_shadow_sha256": "$s_hash"
}
EOF
    chmod 0640 "$BASELINE" 2>/dev/null || true
    ok "Baseline criado: $BASELINE"
  else
    ok "Baseline já existe: $BASELINE"
  fi
}

# --------- JSON estruturado (para a IA MIND ) ----------
emit_json() {
  section "EXPORT • JSON estruturado"

  export MIND_HOST="$HOST"
  export MIND_BASELINE="$BASELINE"

  if ! have python3; then
    crit "python3 não encontrado. Não foi possível gerar JSON."
    return 0
  fi

  python3 - <<'PY' > "$JSON"
import json, subprocess, os, hashlib
from datetime import datetime

HOST = os.environ.get("MIND_HOST", "")
BASELINE = os.environ.get("MIND_BASELINE", "")

def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True).strip()
    except Exception:
        return ""

def run_lines(cmd):
    out = run(cmd)
    return [line for line in out.splitlines() if line.strip()]

def sha(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read())
        return h.hexdigest()
    except Exception:
        return ""

os_pretty = run(["bash","-lc","grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"'"])
kernel = run(["uname","-r"])
uptime_h = run(["bash","-lc","awk '{print int($1/3600)}' /proc/uptime 2>/dev/null || echo 0"])
loadavg = run(["bash","-lc","cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo N/A"])
mem = run(["bash","-lc","free -m 2>/dev/null || true"])
inodes = run(["bash","-lc","df -i 2>/dev/null || true"])
disk_usage_raw = run_lines(["bash","-lc","df -PTh 2>/dev/null || true"])

uid0 = run(["bash","-lc","awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null"]).split()
sudo_group_users = [x.strip() for x in run(["bash","-lc","getent group sudo 2>/dev/null | cut -d: -f4 || true"]).split(",") if x.strip()]
wheel_group_users = [x.strip() for x in run(["bash","-lc","getent group wheel 2>/dev/null | cut -d: -f4 || true"]).split(",") if x.strip()]
sudoers_sample = run_lines(["bash","-lc","grep -Ev '^\\s*#|^\\s*$' /etc/sudoers 2>/dev/null | head -n 20 || true"])

prl = run(["bash","-lc","awk 'tolower($1)==\"permitrootlogin\"{print tolower($2)}' /etc/ssh/sshd_config 2>/dev/null | tail -n1"])
pwa = run(["bash","-lc","awk 'tolower($1)==\"passwordauthentication\"{print tolower($2)}' /etc/ssh/sshd_config 2>/dev/null | tail -n1"])

ports = run(["bash","-lc","(ss -tunap 2>/dev/null || netstat -tulpn 2>/dev/null) | sed -n '1,60p'"])
ports_raw = run_lines(["bash","-lc","ss -tunlH 2>/dev/null || netstat -tunl 2>/dev/null | tail -n +3 || true"])

ww = run(["bash","-lc","find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -type f -perm -0002 -print 2>/dev/null | head -n 80"])
ww_list = [x for x in ww.splitlines() if x.strip()]

passwd_hash = sha("/etc/passwd")
shadow_hash = sha("/etc/shadow")

baseline = {}
if BASELINE and os.path.exists(BASELINE):
    try:
        with open(BASELINE, "r", encoding="utf-8") as f:
            baseline = json.load(f)
    except Exception:
        baseline = {}

passwd_changed = "unknown"
shadow_changed = "unknown"
if baseline.get("etc_passwd_sha256"):
    passwd_changed = "yes" if baseline["etc_passwd_sha256"] != passwd_hash else "no"
if baseline.get("etc_shadow_sha256"):
    shadow_changed = "yes" if baseline["etc_shadow_sha256"] != shadow_hash else "no"

fw_type = "none"
fw_state = "unknown"
if run(["bash","-lc","command -v ufw >/dev/null 2>&1 && echo yes || echo no"]) == "yes":
    fw_type = "ufw"
    fw_state = run(["bash","-lc","ufw status 2>/dev/null | head -n1"])
elif run(["bash","-lc","command -v iptables >/dev/null 2>&1 && echo yes || echo no"]) == "yes":
    fw_type = "iptables"
    fw_state = "rules_present" if run(["bash","-lc","iptables -S 2>/dev/null | head -n1"]) else "no_rules"

failed = run(["bash","-lc","systemctl --failed --no-pager 2>/dev/null || true"])

disk_usage = []
for line in disk_usage_raw[1:]:
    parts = line.split()
    if len(parts) < 7:
        continue
    filesystem, fstype, size, used, avail, use_perc = parts[:6]
    mountpoint = " ".join(parts[6:])
    try:
        use_percent = int(use_perc.rstrip("%"))
    except ValueError:
        use_percent = None
    disk_usage.append({
        "filesystem": filesystem,
        "type": fstype,
        "size": size,
        "used": used,
        "available": avail,
        "use_percent": use_percent,
        "mountpoint": mountpoint,
    })

listening_ports = []
for line in ports_raw:
    parts = line.split()
    if len(parts) < 4:
        continue

    proto = parts[0].lower()
    if not (proto.startswith("tcp") or proto.startswith("udp")):
        continue

    if proto.startswith("tcp"):
        state = parts[1]
        local_address = parts[3]
    else:
        state = "UNCONN"
        local_address = parts[3]

    port = ""
    if "[" in local_address and "]:" in local_address:
        port = local_address.rsplit("]:", 1)[-1]
    elif ":" in local_address:
        port = local_address.rsplit(":", 1)[-1]

    if not port.isdigit():
        continue

    listening_ports.append({
        "protocol": proto,
        "local_address": local_address,
        "port": int(port),
        "state": state,
    })

pkg = "unknown"
pending = "unknown"
if run(["bash","-lc","command -v apt-get >/dev/null 2>&1 && echo yes || echo no"]) == "yes":
    pkg="apt"
    pending = run(["bash","-lc","apt-get -s upgrade 2>/dev/null | awk '/^Inst /{c++} END{print c+0}'"])
elif run(["bash","-lc","command -v dnf >/dev/null 2>&1 && echo yes || echo no"]) == "yes":
    pkg="dnf"
elif run(["bash","-lc","command -v yum >/dev/null 2>&1 && echo yes || echo no"]) == "yes":
    pkg="yum"

data = {
  "meta": {"tool":"mind_scan","generated_at": datetime.now().isoformat(), "host": HOST},
  "system": {
    "os_pretty": os_pretty,
    "kernel": kernel,
    "uptime_hours": int(uptime_h or 0),
    "loadavg_1_5_15": loadavg,
    "memory_free_m": mem,
    "disk_usage": disk_usage,
    "inodes_df_i": inodes,
  },
  "security": {
    "uid0_users": uid0,
    "privileged_users": {
      "sudo_group": sudo_group_users,
      "wheel_group": wheel_group_users,
      "sudoers_sample": sudoers_sample
    },
    "ssh": {"permit_root_login": prl, "password_authentication": pwa},
    "listening_ports_sample": ports,
    "listening_ports_details": listening_ports,
    "world_writable_sample": ww_list,
    "integrity": {
      "baseline_path": BASELINE,
      "etc_passwd_sha256": passwd_hash,
      "etc_shadow_sha256": shadow_hash,
      "passwd_changed_vs_baseline": passwd_changed,
      "shadow_changed_vs_baseline": shadow_changed
    },
    "firewall": {"type": fw_type, "state": fw_state},
  },
  "services": {"systemd_failed": failed},
  "patching": {"pkg_manager": pkg, "pending_updates_estimate": pending},
}
print(json.dumps(data, indent=2, ensure_ascii=False))
PY

  chmod 0640 "$JSON" 2>/dev/null || true
  ok "JSON gerado: $JSON"
}

# --------- Resumo final ----------
summary() {
  section "RESUMO RÁPIDO"
  info "Objetivo: detectar deslizes comuns e entregar evidências (TXT/JSON) para a MIND responder perguntas."
  info "Pontos checados: sistema, CPU/RAM, disco, inodes, UID0, usuários privilegiados, SSH, portas, world-writable, integridade, firewall, services failed, logs, updates/repos."
  ok "Saídas: $TXT e $JSON"
  ok "Baseline: $BASELINE"
}

main() {
  echo -e "${BLUE}${BOLD}==============================${RESET}"
  echo -e "${BLUE}${BOLD}       MIND SECURITY SCAN      ${RESET}"
  echo -e "${BLUE}${BOLD}==============================${RESET}"

  section "MIND SCAN • Início"
  info "Relatório TXT : $TXT"
  info "Relatório JSON: $JSON"

  collect_system
  collect_inodes
  collect_disk_usage

  collect_security_uid0
  collect_security_privileged_users
  collect_security_ssh
  collect_security_ports
  collect_security_world_writable
  collect_security_integrity
  collect_firewall

  collect_services_failed
  collect_logs_keywords
  collect_updates_repos

  make_baseline_if_needed
  emit_json
  summary

  section "MIND SCAN • Fim"
}

main "$@"

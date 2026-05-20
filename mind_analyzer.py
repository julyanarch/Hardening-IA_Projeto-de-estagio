#!/usr/bin/env python3
import json
import sys
from datetime import datetime
from pathlib import Path

# -------- Cores terminal --------
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"
BOLD = "\033[1m"

HIGH_DISK_THRESHOLD = 90
WARN_DISK_THRESHOLD = 85
HIGH_PENDING_UPDATES = 20
RISKY_PORTS = {21, 23, 3389, 5432, 6379, 27017}


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_text(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_load_1m(value):
    try:
        return float(str(value).split()[0])
    except (TypeError, ValueError, IndexError):
        return 0.0


def extract_failed_services(raw_value):
    failed = []
    for line in str(raw_value or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("UNIT ") or stripped.startswith("0 loaded units listed."):
            continue
        if ".service" in stripped:
            failed.append(stripped)
    return failed


def build_ai_context(data):
    security = data.get("security", {})
    system = data.get("system", {})
    patching = data.get("patching", {})

    disk_usage = system.get("disk_usage", [])
    critical_disks = [
        disk for disk in disk_usage
        if to_int(disk.get("use_percent"), default=-1) >= HIGH_DISK_THRESHOLD
    ]
    warning_disks = [
        disk for disk in disk_usage
        if WARN_DISK_THRESHOLD <= to_int(disk.get("use_percent"), default=-1) < HIGH_DISK_THRESHOLD
    ]

    privileged = security.get("privileged_users", {})
    elevated_users = sorted(
        set(security.get("uid0_users", []))
        | set(privileged.get("sudo_group", []))
        | set(privileged.get("wheel_group", []))
    )

    open_ports = security.get("listening_ports_details", [])
    risky_ports = [port for port in open_ports if to_int(port.get("port")) in RISKY_PORTS]

    return {
        "critical_disks": critical_disks,
        "warning_disks": warning_disks,
        "elevated_users": elevated_users,
        "open_ports": open_ports,
        "risky_open_ports": risky_ports,
        "pending_updates": to_int(patching.get("pending_updates_estimate"), default=-1),
    }


def risk_engine(data):
    score = 0
    findings = []

    security = data.get("security", {})
    system = data.get("system", {})
    patching = data.get("patching", {})

    # ---------------- SSH ----------------
    ssh = security.get("ssh", {})
    if normalize_text(ssh.get("permit_root_login")) in ("yes", "", "without-password", "prohibit-password"):
        score += 3
        findings.append("SSH permite login root ou está indefinido.")

    if normalize_text(ssh.get("password_authentication")) in ("yes", ""):
        score += 2
        findings.append("SSH com autenticação por senha habilitada.")

    # ---------------- UID 0 / privilégios ----------------
    uid0 = security.get("uid0_users", [])
    if len(uid0) > 1:
        score += 3
        findings.append(f"Usuários adicionais com UID 0 detectados: {uid0}")

    privileged = security.get("privileged_users", {})
    sudo_group = privileged.get("sudo_group", [])
    wheel_group = privileged.get("wheel_group", [])
    elevated_non_root = sorted({*sudo_group, *wheel_group} - {"root"})
    if elevated_non_root:
        score += 2 if len(elevated_non_root) <= 3 else 3
        findings.append(f"Usuários com privilégios administrativos detectados: {elevated_non_root}")

    # ---------------- Firewall ----------------
    fw = security.get("firewall", {})
    if fw.get("type") == "none" or normalize_text(fw.get("state")) in ("unknown", "no_rules", ""):
        score += 3
        findings.append("Firewall ausente ou sem regras.")

    # ---------------- Integridade ----------------
    integ = security.get("integrity", {})
    if integ.get("passwd_changed_vs_baseline") == "yes":
        score += 4
        findings.append("/etc/passwd alterado desde baseline.")
    if integ.get("shadow_changed_vs_baseline") == "yes":
        score += 4
        findings.append("/etc/shadow alterado desde baseline.")

    # ---------------- World Writable ----------------
    ww = security.get("world_writable_sample", [])
    if ww:
        score += 2
        findings.append(f"{len(ww)} arquivos world-writable encontrados (amostra).")

    # ---------------- Disco ----------------
    disk_usage = system.get("disk_usage", [])
    critical_disks = []
    warning_disks = []
    for disk in disk_usage:
        use_percent = to_int(disk.get("use_percent"), default=-1)
        mountpoint = disk.get("mountpoint", "desconhecido")
        if use_percent >= HIGH_DISK_THRESHOLD:
            critical_disks.append(f"{mountpoint} ({use_percent}%)")
        elif use_percent >= WARN_DISK_THRESHOLD:
            warning_disks.append(f"{mountpoint} ({use_percent}%)")

    if critical_disks:
        score += 4
        findings.append(f"Discos críticos com uso acima de {HIGH_DISK_THRESHOLD}%: {critical_disks}")
    elif warning_disks:
        score += 2
        findings.append(f"Discos em atenção com uso acima de {WARN_DISK_THRESHOLD}%: {warning_disks}")

    # ---------------- Portas abertas ----------------
    listening_ports = security.get("listening_ports_details", [])
    if listening_ports:
        total_ports = len(listening_ports)
        risky_ports = sorted(
            {to_int(port.get('port')) for port in listening_ports if to_int(port.get("port")) in RISKY_PORTS}
        )
        if risky_ports:
            score += 3
            findings.append(f"Portas sensíveis expostas em escuta: {risky_ports}")
        elif total_ports >= 10:
            score += 2
            findings.append(f"Servidor com muitas portas em escuta: {total_ports}")

    # ---------------- Load Average ----------------
    load1 = parse_load_1m(system.get("loadavg_1_5_15", "0"))
    if load1 > 5:
        score += 1
        findings.append(f"Load elevado (1min): {load1}")

    # ---------------- Serviços falhos ----------------
    failed_services = extract_failed_services(data.get("services", {}).get("systemd_failed", ""))
    if failed_services:
        score += 1
        findings.append(f"Serviços systemd em falha detectados: {len(failed_services)}")

    # ---------------- Patching ----------------
    pending_updates = to_int(patching.get("pending_updates_estimate"), default=-1)
    if pending_updates >= HIGH_PENDING_UPDATES:
        score += 2
        findings.append(f"Quantidade alta de updates pendentes: {pending_updates}")
    elif pending_updates >= 1:
        score += 1
        findings.append(f"Updates pendentes detectados: {pending_updates}")

    if score >= 12:
        level = "ALTO"
    elif score >= 6:
        level = "MÉDIO"
    else:
        level = "BAIXO"

    return level, score, findings


def generate_recommendations(findings):
    recommendations = []
    for finding in findings:
        if "SSH permite login root" in finding:
            recommendations.append("Definir 'PermitRootLogin no' no sshd_config.")
        if "senha habilitada" in finding:
            recommendations.append("Desativar 'PasswordAuthentication yes' e usar chave pública.")
        if "UID 0" in finding:
            recommendations.append("Revisar contas com UID 0 e remover privilégios desnecessários.")
        if "privilégios administrativos" in finding:
            recommendations.append("Validar membros de sudo/wheel conforme a matriz de acesso mínimo.")
        if "Firewall" in finding:
            recommendations.append("Ativar UFW ou aplicar regras iptables corporativas.")
        if "passwd" in finding or "shadow" in finding:
            recommendations.append("Investigar alterações nos arquivos críticos imediatamente.")
        if "world-writable" in finding:
            recommendations.append("Revisar permissões de arquivos com chmod apropriado.")
        if "Discos críticos" in finding or "Discos em atenção" in finding:
            recommendations.append("Liberar espaço ou ampliar volume antes de impacto operacional.")
        if "Portas sensíveis" in finding or "muitas portas em escuta" in finding:
            recommendations.append("Revisar exposição de serviços e restringir portas não essenciais.")
        if "Load elevado" in finding:
            recommendations.append("Analisar processos com maior consumo de CPU e fila de execução.")
        if "Serviços systemd em falha" in finding:
            recommendations.append("Validar os serviços falhos e confirmar impacto no ambiente.")
        if "updates pendentes" in finding.lower():
            recommendations.append("Planejar janela de patching para reduzir exposição por versões desatualizadas.")
    return sorted(set(recommendations))


def generate_mind_report(data, level, score, findings, output_path: Path):
    ai_context = build_ai_context(data)
    report = {
        "meta": {
            "generated_at": datetime.now().isoformat(),
            "tool": "mind_analyzer",
        },
        "host": data.get("meta", {}).get("host", "desconhecido"),
        "risk_level": level,
        "risk_score": score,
        "findings": findings,
        "recommendation_summary": generate_recommendations(findings),
        "ai_context": ai_context,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 mind_analyzer.py <mind_scan_arquivo.json>")
        sys.exit(1)

    input_path = Path(sys.argv[1])

    if not input_path.exists():
        print(f"{RED}{BOLD}[ERRO]{RESET} Arquivo não encontrado: {input_path}")
        sys.exit(2)

    data = load_json(input_path)
    level, score, findings = risk_engine(data)

    if level == "ALTO":
        level_color = RED
    elif level == "MÉDIO":
        level_color = YELLOW
    else:
        level_color = GREEN

    output_path = input_path.parent / f"mind_risk_{input_path.stem}.json"
    generate_mind_report(data, level, score, findings, output_path)

    print(f"{BLUE}{BOLD}--------------------------------------------------{RESET}")
    print(f"{BOLD}Host analisado :{RESET} {data.get('meta', {}).get('host', 'desconhecido')}")
    print(f"{BOLD}Nível de risco :{RESET} {level_color}{BOLD}{level}{RESET}")
    print(f"{BOLD}Score          :{RESET} {BLUE}{score}{RESET}")
    print(f"{BOLD}Achados:{RESET}")
    if findings:
        for finding in findings:
            print(f" {RED}- {finding}{RESET}")
    else:
        print(f" {GREEN}- Nenhum achado relevante com as regras atuais.{RESET}")
    print(f"{BLUE}{BOLD}--------------------------------------------------{RESET}")
    print(f"{BOLD}Arquivo gerado:{RESET} {GREEN}{output_path}{RESET}")


if __name__ == "__main__":
    main()

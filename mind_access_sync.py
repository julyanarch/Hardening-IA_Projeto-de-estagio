#!/usr/bin/env python3
"""
MIND Access Sync

Le um workbook Excel como fonte de verdade para acessos, normaliza os usuarios
e gera um plano de sincronizacao para o servidor Linux.

O script nao executa alteracoes por conta propria. Ele prepara o diff entre a
planilha e os usuarios locais, gerando TXT e JSON para auditoria, IA interna e
futuras automacoes via Ansible.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import unicodedata
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as xml_escape

APP = "mind_access_sync"
DEFAULT_SHEET = ""
MANAGED_UID_MIN = 1000
DEFAULT_TEMPLATE_PATH = "acessos_exemplo.xlsx"

TEMPLATE_HEADERS = [
    "nome_completo",
    "usuario_linux",
    "status",
    "grupo",
    "ticket",
    "observacao",
]

TEMPLATE_ROWS = [
    {
        "nome_completo": "João Paulo Araujo",
        "usuario_linux": "joao.araujo",
        "status": "ativo",
        "grupo": "",
        "ticket": "EXEMPLO-0001",
        "observacao": "Exemplo de acesso ativo",
    },
    {
        "nome_completo": "Douglas Michel Da Silva",
        "usuario_linux": "douglas.silva",
        "status": "ativo",
        "grupo": "",
        "ticket": "EXEMPLO-0002",
        "observacao": "Exemplo de acesso ativo",
    },
    {
        "nome_completo": "Julyana Silva da Rocha",
        "usuario_linux": "julyana.rocha",
        "status": "ativo",
        "grupo": "",
        "ticket": "EXEMPLO-0003",
        "observacao": "Exemplo de acesso ativo",
    },
    {
        "nome_completo": "Odair Batista Gonçalves dos Santos",
        "usuario_linux": "odair.santos",
        "status": "ativo",
        "grupo": "",
        "ticket": "EXEMPLO-0004",
        "observacao": "Exemplo de acesso ativo",
    },
    {
        "nome_completo": "Carlos Roitman Amaral Maceno",
        "usuario_linux": "carlos.maceno",
        "status": "ativo",
        "grupo": "",
        "ticket": "EXEMPLO-0005",
        "observacao": "Exemplo de acesso ativo",
    },
]

PROTECTED_USERS = {
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "gnats",
    "nobody",
    "systemd-network",
    "systemd-resolve",
    "messagebus",
    "sshd",
}

ACTIVE_VALUES = {"ativo", "active", "sim", "yes", "true", "1"}
INACTIVE_VALUES = {"inativo", "inactive", "nao", "não", "no", "false", "0", "disabled"}
STOPWORDS = {"da", "de", "do", "das", "dos", "e"}

HEADER_ALIASES = {
    "nome_completo": {"nome_completo", "nome", "colaborador", "colaborador_nome", "nome_do_colaborador"},
    "usuario_linux": {"usuario_linux", "usuario", "username", "login", "usuario_linux_padrao"},
    "status": {"status", "situacao", "situacao_do_acesso", "estado"},
    "grupo": {"grupo", "grupo_linux", "role"},
    "ticket": {"ticket", "chamado", "incidente", "solicitacao"},
    "observacao": {"observacao", "obs", "comentario", "comentarios"},
}

NS_MAIN = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
NS_REL = {"rel": "http://schemas.openxmlformats.org/package/2006/relationships"}


@dataclass
class AccessEntry:
    row_number: int
    nome_completo: str
    usuario_linux: str
    status: str
    grupo: str
    ticket: str
    observacao: str
    source_state: str
    host_exists: bool
    managed_host_user: bool
    planned_action: str
    notes: List[str]


def normalize_text(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    text = text.replace("\r", " ").replace("\n", " ")
    return re.sub(r"\s+", " ", text)


def column_letter(index: int) -> str:
    result = ""
    while index > 0:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def strip_accents(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


def slugify(value: str) -> str:
    value = strip_accents(normalize_text(value)).lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_")


def normalize_username(value: str) -> str:
    value = strip_accents(normalize_text(value)).lower()
    value = re.sub(r"[^a-z0-9_.-]+", "", value)
    return value.strip("._-")


def derive_username_from_name(full_name: str) -> str:
    text = strip_accents(normalize_text(full_name)).lower()
    parts = [part for part in re.split(r"\s+", text) if part and part not in STOPWORDS]
    if not parts:
        return ""
    if len(parts) == 1:
        return normalize_username(parts[0])
    candidate = f"{parts[0]}.{parts[-1]}"
    return normalize_username(candidate)


def normalize_status(value: str) -> str:
    cleaned = slugify(value)
    if not cleaned:
        return "ativo"
    if cleaned in ACTIVE_VALUES:
        return "ativo"
    if cleaned in INACTIVE_VALUES:
        return "inativo"
    return cleaned


def is_protected_user(username: str) -> bool:
    return username in PROTECTED_USERS


def run_command(command: List[str]) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def get_host_accounts() -> Dict[str, Dict[str, object]]:
    accounts: Dict[str, Dict[str, object]] = {}
    output = run_command(["getent", "passwd"])
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, _, uid, gid, gecos, home, shell = parts[:7]
        try:
            uid_int = int(uid)
            gid_int = int(gid)
        except ValueError:
            continue
        accounts[username] = {
            "uid": uid_int,
            "gid": gid_int,
            "gecos": gecos,
            "home": home,
            "shell": shell,
        }
    return accounts


def get_managed_host_users(accounts: Dict[str, Dict[str, object]], uid_min: int) -> Dict[str, Dict[str, object]]:
    managed: Dict[str, Dict[str, object]] = {}
    for username, meta in accounts.items():
        if username in PROTECTED_USERS:
            continue
        if int(meta.get("uid", 0)) < uid_min:
            continue
        managed[username] = meta
    return managed


def column_index_from_ref(ref: str) -> int:
    letters = re.match(r"^[A-Z]+", ref.upper())
    if not letters:
        return 0
    total = 0
    for char in letters.group(0):
        total = total * 26 + (ord(char) - ord("A") + 1)
    return total


def parse_shared_strings(zf: zipfile.ZipFile) -> List[str]:
    try:
        data = zf.read("xl/sharedStrings.xml")
    except KeyError:
        return []

    root = ET.fromstring(data)
    shared: List[str] = []
    for si in root.findall("main:si", NS_MAIN):
        fragments: List[str] = []
        for node in si.iter():
            if node.tag.split("}", 1)[-1] == "t" and node.text is not None:
                fragments.append(node.text)
        shared.append("".join(fragments))
    return shared


def normalize_xlsx_target(target: str) -> str:
    target = target.lstrip("/")
    if target.startswith("xl/"):
        return target
    return f"xl/{target}"


def resolve_sheet_path(zf: zipfile.ZipFile, workbook_name: str) -> Tuple[str, str]:
    workbook = ET.fromstring(zf.read("xl/workbook.xml"))
    rels = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
    rel_map = {
        rel.attrib["Id"]: rel.attrib["Target"]
        for rel in rels.findall("rel:Relationship", NS_REL)
    }

    sheets_node = workbook.find("main:sheets", NS_MAIN)
    if sheets_node is None:
        raise ValueError("Nenhuma sheet encontrada no workbook.")

    sheets: List[Tuple[str, str]] = []
    for sheet in sheets_node.findall("main:sheet", NS_MAIN):
        name = sheet.attrib.get("name", "")
        rel_id = sheet.attrib.get(
            "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id", ""
        )
        target = rel_map.get(rel_id, "")
        sheets.append((name, target))

    if not sheets:
        raise ValueError("Nenhuma sheet encontrada no workbook.")

    if workbook_name:
        for name, target in sheets:
            if name == workbook_name:
                return name, normalize_xlsx_target(target)
        available = ", ".join(name for name, _ in sheets)
        raise ValueError(f"Sheet '{workbook_name}' nao encontrada. Disponiveis: {available}")

    return sheets[0][0], normalize_xlsx_target(sheets[0][1])


def parse_cell_value(cell: ET.Element, shared_strings: List[str]) -> str:
    cell_type = cell.attrib.get("t", "")
    value_node = cell.find("main:v", NS_MAIN)
    if cell_type == "s" and value_node is not None and value_node.text is not None:
        try:
            return shared_strings[int(value_node.text)]
        except (ValueError, IndexError):
            return ""
    if cell_type == "inlineStr":
        texts = [node.text or "" for node in cell.iter() if node.tag.split("}", 1)[-1] == "t"]
        return "".join(texts)
    if value_node is not None and value_node.text is not None:
        return value_node.text
    return ""


def resolve_header_name(raw_value: str, position: int) -> str:
    key = slugify(raw_value)
    for canonical, aliases in HEADER_ALIASES.items():
        if key == canonical or key in aliases:
            return canonical
    if key:
        return key
    return f"col_{position + 1}"


def parse_xlsx_rows(workbook_path: Path, sheet_name: str) -> Tuple[List[str], List[Tuple[int, List[str]]]]:
    with zipfile.ZipFile(workbook_path) as zf:
        _, target = resolve_sheet_path(zf, sheet_name)
        shared_strings = parse_shared_strings(zf)
        sheet_root = ET.fromstring(zf.read(target))

    sheet_data = sheet_root.find("main:sheetData", NS_MAIN)
    if sheet_data is None:
        raise ValueError("A sheet nao possui dados.")

    rows: List[Tuple[int, List[str]]] = []
    for row in sheet_data.findall("main:row", NS_MAIN):
        row_number = int(row.attrib.get("r", str(len(rows) + 1)))
        cells: Dict[int, str] = {}
        max_index = 0
        for cell in row.findall("main:c", NS_MAIN):
            ref = cell.attrib.get("r", "")
            index = column_index_from_ref(ref)
            if index <= 0:
                continue
            cells[index] = parse_cell_value(cell, shared_strings)
            max_index = max(max_index, index)
        values = [cells.get(index, "") for index in range(1, max_index + 1)]
        rows.append((row_number, values))

    if not rows:
        raise ValueError("Workbook sem linhas.")

    header_row = rows[0][1]
    headers = [resolve_header_name(value, position) for position, value in enumerate(header_row)]
    return headers, rows[1:]


def build_entry_map(headers: List[str], rows: List[Tuple[int, List[str]]]) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    for row_number, values in rows:
        record = {"_row_number": str(row_number)}
        for index, header in enumerate(headers):
            record[header] = normalize_text(values[index]) if index < len(values) else ""
        entries.append(record)
    return entries


def build_access_entries(entries: List[Dict[str, str]], managed_host_users: Dict[str, Dict[str, object]]) -> List[AccessEntry]:
    access_entries: List[AccessEntry] = []
    for record in entries:
        row_number = int(record.get("_row_number", "0") or "0")
        full_name = normalize_text(record.get("nome_completo", ""))
        username_raw = normalize_text(record.get("usuario_linux", ""))
        status_value = normalize_status(record.get("status", ""))
        group_name = normalize_text(record.get("grupo", ""))
        ticket = normalize_text(record.get("ticket", ""))
        observation = normalize_text(record.get("observacao", ""))

        notes: List[str] = []
        username = normalize_username(username_raw) if username_raw else derive_username_from_name(full_name)
        if not username:
            notes.append("nao foi possivel derivar o usuario Linux")

        if not full_name and not username:
            access_entries.append(
                AccessEntry(
                    row_number=row_number,
                    nome_completo="",
                    usuario_linux="",
                    status=status_value,
                    grupo=group_name,
                    ticket=ticket,
                    observacao=observation,
                    source_state="invalid",
                    host_exists=False,
                    managed_host_user=False,
                    planned_action="review",
                    notes=["linha sem nome_completo nem usuario_linux"],
                )
            )
            continue

        if not username:
            source_state = "review"
        elif status_value == "ativo":
            source_state = "ativo"
        elif status_value == "inativo":
            source_state = "inativo"
        else:
            source_state = "review"

        host_exists = bool(username and username in managed_host_users)
        managed_host_user = host_exists

        if not username:
            planned_action = "review"
        elif is_protected_user(username):
            planned_action = "blocked"
            notes.append("usuario protegido nao pode ser gerenciado")
        elif source_state == "ativo":
            planned_action = "keep" if host_exists else "create"
        elif source_state == "inativo":
            planned_action = "remove" if host_exists else "skip"
        else:
            planned_action = "review"
            notes.append("status nao reconhecido")

        if source_state == "ativo" and host_exists:
            notes.append("usuario ja existe no host")
        elif source_state == "ativo" and not host_exists:
            notes.append("usuario ausente no host")
        elif source_state == "inativo" and host_exists:
            notes.append("usuario presente no host mas marcado como inativo")
        elif source_state == "inativo" and not host_exists:
            notes.append("usuario ausente e inativo")

        access_entries.append(
            AccessEntry(
                row_number=row_number,
                nome_completo=full_name,
                usuario_linux=username,
                status=status_value,
                grupo=group_name,
                ticket=ticket,
                observacao=observation,
                source_state=source_state,
                host_exists=host_exists,
                managed_host_user=managed_host_user,
                planned_action=planned_action,
                notes=notes,
            )
        )

    return access_entries


def build_report(access_entries: List[AccessEntry], managed_host_users: Dict[str, Dict[str, object]]) -> Dict[str, object]:
    active_users = {entry.usuario_linux for entry in access_entries if entry.source_state == "ativo" and entry.usuario_linux}
    host_users = set(managed_host_users.keys())

    to_create = sorted(active_users - host_users)
    to_keep = sorted(active_users & host_users)
    to_remove = sorted(host_users - active_users)

    counts = {
        "sheet_rows": len(access_entries),
        "active_entries": sum(1 for entry in access_entries if entry.source_state == "ativo"),
        "inactive_entries": sum(1 for entry in access_entries if entry.source_state == "inativo"),
        "create": len(to_create),
        "keep": len(to_keep),
        "remove": len(to_remove),
        "review": sum(1 for entry in access_entries if entry.planned_action == "review"),
        "blocked": sum(1 for entry in access_entries if entry.planned_action == "blocked"),
    }

    return {
        "summary": counts,
        "diff": {
            "to_create": to_create,
            "to_keep": to_keep,
            "to_remove": to_remove,
        },
    }


def render_text_report(meta: Dict[str, object], access_entries: List[AccessEntry], report: Dict[str, object]) -> str:
    lines: List[str] = []

    def add(line: str = "") -> None:
        lines.append(line)

    add("============================================================")
    add("MIND ACCESS SYNC")
    add("============================================================")
    add(f"Generated at : {meta['generated_at']}")
    add(f"Host         : {meta['host']}")
    add(f"Workbook     : {meta['workbook']}")
    add(f"Sheet        : {meta['sheet'] or '(primeira planilha)'}")
    add(f"Managed UID  : >= {meta['managed_uid_min']}")
    add("")
    add("Resumo")
    add(f"  Sheet rows    : {report['summary']['sheet_rows']}")
    add(f"  Active rows   : {report['summary']['active_entries']}")
    add(f"  Inactive rows : {report['summary']['inactive_entries']}")
    add(f"  To create     : {report['summary']['create']}")
    add(f"  To keep       : {report['summary']['keep']}")
    add(f"  To remove     : {report['summary']['remove']}")
    add(f"  Review        : {report['summary']['review']}")
    add(f"  Blocked       : {report['summary']['blocked']}")
    add("")
    add("Diff")
    add(f"  Create: {', '.join(report['diff']['to_create']) or '-'}")
    add(f"  Keep  : {', '.join(report['diff']['to_keep']) or '-'}")
    add(f"  Remove: {', '.join(report['diff']['to_remove']) or '-'}")
    add("")
    add("Linhas normalizadas")
    for entry in access_entries:
        add(
            f"  row {entry.row_number}: {entry.usuario_linux or '-'} "
            f"({entry.source_state}) -> {entry.planned_action}"
        )
        if entry.notes:
            add(f"    notes: {'; '.join(entry.notes)}")
    add("")
    add("Nota")
    add("  Este script gera o plano. A execucao real pode ser ligada depois no Ansible.")

    return "\n".join(lines) + "\n"


def prepare_output_dir(path: Optional[str]) -> Path:
    out_dir = Path(path) if path else Path("/var/log/mind")
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir
    except PermissionError:
        fallback = Path.cwd() / "mind_outputs"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MIND Access Sync planner from Excel workbook")
    parser.add_argument("--workbook", default="", help="Path to the .xlsx workbook")
    parser.add_argument("--sheet", default=DEFAULT_SHEET, help="Sheet name to read. If omitted, the first sheet is used.")
    parser.add_argument("--output-dir", default=None, help="Output directory for TXT/JSON")
    parser.add_argument("--uid-min", type=int, default=MANAGED_UID_MIN, help="Minimum UID to consider managed users")
    parser.add_argument("--create-template", action="store_true", help="Create a sample workbook and exit")
    parser.add_argument("--template-path", default=DEFAULT_TEMPLATE_PATH, help="Path for the generated sample workbook")
    return parser.parse_args()


def template_sheet_xml(headers: List[str], rows: List[Dict[str, str]], sheet_name: str = "Acessos") -> str:
    all_rows = [dict(zip(headers, headers))]
    all_rows.extend(rows)
    last_col = column_letter(len(headers))
    last_row = len(all_rows)
    dimension_ref = f"A1:{last_col}{last_row}"

    col_widths = [28, 22, 14, 16, 16, 34]
    sheet_rows: List[str] = []
    for row_index, row_data in enumerate(all_rows, start=1):
        cell_xml: List[str] = []
        for col_index, header in enumerate(headers, start=1):
            value = row_data.get(header, "")
            ref = f"{column_letter(col_index)}{row_index}"
            style_id = "1" if row_index == 1 else ("2" if row_index % 2 == 0 else "3")
            cell_xml.append(
                f'<c r="{ref}" s="{style_id}" t="inlineStr"><is><t>{xml_escape(str(value))}</t></is></c>'
            )
        height_attr = ' ht="24" customHeight="1"' if row_index == 1 else ""
        sheet_rows.append(f'<row r="{row_index}"{height_attr}>{"".join(cell_xml)}</row>')

    cols_xml = "".join(
        f'<col min="{index}" max="{index}" width="{width}" customWidth="1"/>'
        for index, width in enumerate(col_widths, start=1)
    )

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<dimension ref=\"{dimension_ref}\"/>"
        "<sheetViews><sheetView workbookViewId=\"0\"><pane ySplit=\"1\" topLeftCell=\"A2\" "
        "activePane=\"bottomLeft\" state=\"frozen\"/><selection pane=\"bottomLeft\" "
        "activeCell=\"A2\" sqref=\"A2\"/></sheetView></sheetViews>"
        f"<cols>{cols_xml}</cols>"
        f"<sheetData>{''.join(sheet_rows)}</sheetData>"
        f"<autoFilter ref=\"{dimension_ref}\"/>"
        "</worksheet>"
    )


def xlsx_content_types_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        "</Types>"
    )


def xlsx_root_rels_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )


def xlsx_workbook_xml(sheet_name: str = "Acessos") -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets><sheet name="{xml_escape(sheet_name)}" sheetId="1" r:id="rId1"/></sheets>'
        "</workbook>"
    )


def xlsx_workbook_rels_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        "</Relationships>"
    )


def xlsx_styles_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<fonts count=\"2\">"
        "<font><sz val=\"11\"/><color theme=\"1\"/><name val=\"Calibri\"/><family val=\"2\"/></font>"
        "<font><sz val=\"11\"/><b/><color rgb=\"FFFFFFFF\"/><name val=\"Calibri\"/><family val=\"2\"/></font>"
        "</fonts>"
        "<fills count=\"4\">"
        "<fill><patternFill patternType=\"none\"/></fill>"
        "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FF1F4E78\"/><bgColor indexed=\"64\"/></patternFill></fill>"
        "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFF7FAFC\"/><bgColor indexed=\"64\"/></patternFill></fill>"
        "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFFFFFFF\"/><bgColor indexed=\"64\"/></patternFill></fill>"
        "</fills>"
        "<borders count=\"2\">"
        "<border><left/><right/><top/><bottom/><diagonal/></border>"
        "<border>"
        "<left style=\"thin\"><color rgb=\"FFD9E2F3\"/></left>"
        "<right style=\"thin\"><color rgb=\"FFD9E2F3\"/></right>"
        "<top style=\"thin\"><color rgb=\"FFD9E2F3\"/></top>"
        "<bottom style=\"thin\"><color rgb=\"FFD9E2F3\"/></bottom>"
        "<diagonal/>"
        "</border>"
        "</borders>"
        "<cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>"
        "<cellXfs count=\"4\">"
        "<xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"1\" xfId=\"0\" applyBorder=\"1\"/>"
        "<xf numFmtId=\"0\" fontId=\"1\" fillId=\"1\" borderId=\"1\" xfId=\"0\" applyFill=\"1\" applyFont=\"1\" applyBorder=\"1\" applyAlignment=\"1\"><alignment horizontal=\"center\" vertical=\"center\"/></xf>"
        "<xf numFmtId=\"0\" fontId=\"0\" fillId=\"2\" borderId=\"1\" xfId=\"0\" applyFill=\"1\" applyBorder=\"1\"><alignment vertical=\"center\"/></xf>"
        "<xf numFmtId=\"0\" fontId=\"0\" fillId=\"3\" borderId=\"1\" xfId=\"0\" applyFill=\"1\" applyBorder=\"1\"><alignment vertical=\"center\"/></xf>"
        "</cellXfs>"
        "<cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles>"
        "</styleSheet>"
    )


def write_template_workbook(output_path: Path, sheet_name: str = "Acessos") -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", xlsx_content_types_xml())
        zf.writestr("_rels/.rels", xlsx_root_rels_xml())
        zf.writestr("xl/workbook.xml", xlsx_workbook_xml(sheet_name))
        zf.writestr("xl/_rels/workbook.xml.rels", xlsx_workbook_rels_xml())
        zf.writestr("xl/styles.xml", xlsx_styles_xml())
        zf.writestr("xl/worksheets/sheet1.xml", template_sheet_xml(TEMPLATE_HEADERS, TEMPLATE_ROWS, sheet_name))


def main() -> int:
    args = parse_args()

    if args.create_template:
        template_path = Path(args.template_path)
        write_template_workbook(template_path, "Acessos")
        print(f"[OK] Planilha exemplo criada: {template_path}")
        return 0

    if not args.workbook:
        print("[ERRO] Informe --workbook ou use --create-template.")
        return 1

    workbook = Path(args.workbook)

    if not workbook.exists():
        print(f"[ERRO] Workbook nao encontrado: {workbook}")
        return 2
    if workbook.suffix.lower() != ".xlsx":
        print(f"[ERRO] O script espera um arquivo .xlsx: {workbook}")
        return 3

    out_dir = prepare_output_dir(args.output_dir)
    host = run_command(["hostname", "-s"]) or run_command(["hostname"]) or "unknown-host"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = out_dir / f"{APP}_{host}_{stamp}.txt"
    json_path = out_dir / f"{APP}_{host}_{stamp}.json"

    try:
        headers, rows = parse_xlsx_rows(workbook, args.sheet)
    except Exception as exc:
        print(f"[ERRO] Falha ao ler workbook: {exc}")
        return 4

    normalized_rows = build_entry_map(headers, rows)
    host_accounts = get_host_accounts()
    managed_host_users = get_managed_host_users(host_accounts, args.uid_min)
    access_entries = build_access_entries(normalized_rows, managed_host_users)
    report = build_report(access_entries, managed_host_users)

    meta = {
        "tool": APP,
        "generated_at": datetime.now().isoformat(),
        "host": host,
        "workbook": str(workbook),
        "sheet": args.sheet,
        "managed_uid_min": args.uid_min,
    }

    json_payload = {
        "meta": meta,
        "summary": report["summary"],
        "diff": report["diff"],
        "entries": [asdict(entry) for entry in access_entries],
    }

    txt_path.write_text(render_text_report(meta, access_entries, report), encoding="utf-8")
    json_path.write_text(json.dumps(json_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    print(render_text_report(meta, access_entries, report), end="")
    print(f"[OK] TXT  gerado: {txt_path}")
    print(f"[OK] JSON gerado: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

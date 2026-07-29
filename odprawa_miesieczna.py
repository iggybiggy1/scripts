#!/usr/bin/env python3
"""
End-to-end CVE extraction + configuration checks (NO CWE lookups / NO CWE mapping).

USAGE:
  python script.py <root_folder_with_subfolders> [group_mapping_file.xlsx]

Examples:
  python script.py /data/root
  python script.py /data/root domeny_przypisane.xlsx
  python script.py /data/root /full/path/to/domeny_przypisane.xlsx

Group mapping Excel format:
  Each column header is a group name.
  Each non-empty cell under that column is a domain assigned to that group.

  Example:
    JON      PUoOO
    aaa.pl   bbb.pl
    ddd.pl   eee.pl

If mapping file is NOT passed explicitly:
  - the script will auto-detect the first suitable .xlsx file in the root folder
  - excluding generated files like findings_all_*.xlsx and diff.xlsx

IMPORTANT (subdomain grouping):
  - If the scan contains subdomains (e.g., example.aaa.pl) but the mapping workbook
    contains only the main domain (e.g., aaa.pl), the script will:
      * normalize domain
      * try exact match
      * then try suffix matches by stripping left-most labels:
          example.aaa.pl -> aaa.pl -> pl (stops at 2 labels minimum, so "pl" won't be used)
    This assigns the subdomain to the group of the main domain.

Outputs:
  - Per-folder Excel: <root>/Excel/findings_<Folder>_<STAMP>.xlsx
  - Combined Excel ONLY in root: <root>/findings_all_<STAMP>.xlsx
  - Diff text report in root: <root>/diff.txt comparing previous findings_all_*.xlsx vs new
  - Diff Excel report in root: <root>/diff.xlsx comparing previous findings_all_*.xlsx vs new

Diff behavior:
  - diff.txt includes:
      * added CVEs / config issues
      * removed CVEs / config issues
      * unchanged CVEs / config issues
  - diff.xlsx includes ONLY:
      * sheet: CVE_Folder_Changes
      * sheet: Config_Changes
  - diff.xlsx does NOT include:
      * Summary
      * CVE_DomainIP_Changes

Status mapping in diff.xlsx:
  - added -> dodane
  - removed -> usuniete
  - unchanged -> bez zmiany

For configuration issues:
  - domains linked to the configuration vulnerability are preserved in normal outputs
  - diff.xlsx Config_Changes also contains Domains and Group
"""

import os
import re
import sys
import glob
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set

import pandas as pd

# ---------------------------------------------------------------------------
# Configuration / constants
# ---------------------------------------------------------------------------

KNOWN_SUBFOLDERS = ["szpitale", "instytuty", "ron", "szkoly", "reszta", "pgz", "muzea"]

STATUS_ADDED = "dodane"
STATUS_REMOVED = "usuniete"
STATUS_UNCHANGED = "bez zmiany"

# ---------------------------------------------------------------------------
# Configuration-like checks ("konfiguracyjne")
# ---------------------------------------------------------------------------

CONFIG_CHECKS = [
    {"name": "Brak nagłówków zabezpieczeń HTTP", "pattern": r"Brak nagłówków bezpieczeństwa:"},
    {"name": "Brak ustawienia polityki SameSite dla ciasteczek", "pattern": r"Brak ustawienia ciasteczka SameSite"},
    {"name": "Zastosowanie niewystarczająco silnego klucza w DKIM", "pattern": r"DKIM z krótkim kluczem"},
    {"name": "Wykrycie klucza API Google w kodzie źródłowym", "pattern": r"Google API Key"},
    {"name": "Dostęp do zmiennych środowiskowych przez cgi-bin", "pattern": r"cgi-bin/printenv\.pl"},
    {"name": "Ujawnienie wrażliwych logów Roundcube", "pattern": r"Roundcube log disclosure"},
    {"name": "Wykrycie formularza logowania do WordPressa", "pattern": r"WordPress login"},
    {"name": "Zezwolenie na logowanie anonimowe FTP", "pattern": r"anonymous login"},
    {"name": "Publicznie dostępne repozytorium Git", "pattern": r"Repozytorium Git dostepne publicznie"},
    {"name": "Ujawnienie konfiguracji GitHub workflows", "pattern": r"GitHub workflows disclosure"},
    {"name": "Błędna konfiguracja narzędzia Behat", "pattern": r"Behat config"},
    {"name": "Ujawnienie listy konfiguracji serwera", "pattern": r"Configuration listing"},
    {"name": "Wykrycie publicznego dostępu do phpinfo", "pattern": r"Wykryto phpinfo"},
    {"name": "Zewnętrzny dostęp do bazy danych", "pattern": r"Następujące serwery mają otwarty port bazy danych"},
    {"name": "Nieaktualne wersje CMS/wtyczek", "pattern": r"Nieaktualne wersje CMS lub wtyczek"},
    {"name": "Brak przekierowania z HTTP na HTTPS", "pattern": r"Następujące adresy nie przekierowują z http:// na https://"},
    {
        "name": "Problemy z konfiguracją TLS/SSL",
        "pattern": (
            r"Przestarzala wersja protokolu TLS|"
            r"Następujące adresy zwracają certyfikaty SSL/TLS wystawione na niepoprawne domeny|"
            r"Certyfikat niepodpisany przez zaufany CA"
        ),
    },
    {
        "name": "Nieprawidłowa konfiguracja mechanizmów weryfikacji nadawcy wiadomości e-mail (DMARC, SPF, DKIM)",
        "pattern": (
            r"Polityka DMARC jest ustawiona na 'none'|"
            r"Domena [a-zA-Z0-9-]+\.[a-zA-Z]{2,} nie wskazuje, że przyjmuje raporty DMARC|"
            r"Nie znaleziono poprawnego rekordu DMARC|"
            r"Polityka DMARC jest ustawiona na 'none', co oznacza|"
            r"Następujące domeny nie mają poprawnie skonfigurowanych mechanizmów weryfikacji nadawcy"
        ),
    },
]

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def log_line(msg: str, log_fp):
    print(msg)
    if log_fp:
        log_fp.write(msg + "\n")
        log_fp.flush()

def ts_suffix() -> str:
    return datetime.now().strftime("%d%m%y_%H%M")

# ---------------------------------------------------------------------------
# Group mapping helpers (Excel-based + suffix/subdomain matching)
# ---------------------------------------------------------------------------

def normalize_domain_key(value: str) -> str:
    """
    Strong normalization for domain-like values:
      - lowercase
      - strip whitespace
      - remove http:// or https://
      - remove path/query/fragment
      - remove port
      - strip trailing dot
    """
    if value is None:
        return ""

    s = str(value).strip().lower()
    if not s:
        return ""

    s = re.sub(r"^\s*https?://", "", s, flags=re.IGNORECASE)
    s = s.split("/")[0]
    s = s.split("?")[0]
    s = s.split("#")[0]
    s = s.rstrip(".")
    if ":" in s:
        host, port = s.rsplit(":", 1)
        if port.isdigit():
            s = host

    return s.strip()

def domain_suffix_candidates(domain_norm: str) -> List[str]:
    """
    Generate candidates from most-specific to less-specific, but stop at 2 labels minimum.
    Example:
      example.aaa.pl -> ["example.aaa.pl", "aaa.pl"]
    We do NOT include "pl".
    """
    parts = [p for p in domain_norm.split(".") if p]
    if len(parts) < 2:
        return [domain_norm] if domain_norm else []

    cands = []
    for i in range(0, len(parts) - 1):
        suffix = ".".join(parts[i:])
        if suffix.count(".") >= 1:
            cands.append(suffix)

    seen = set()
    out = []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out

def domain_candidate_keys(value: str) -> List[str]:
    """
    Candidates include:
      - normalized value
      - without/with leading www.
      - suffixes (subdomain stripping) for both www/non-www forms
    Returned order is most-specific-first so we prefer the longest match.
    """
    norm = normalize_domain_key(value)
    if not norm:
        return []

    base_forms = [norm]
    if norm.startswith("www."):
        base_forms.append(norm[4:])
    else:
        base_forms.append("www." + norm)

    candidates: List[str] = []
    for base in base_forms:
        candidates.extend(domain_suffix_candidates(base))

    seen = set()
    out = []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out

def resolve_group_mapping_path(root_folder: str, arg_path: Optional[str], log_fp=None) -> Optional[str]:
    """
    Resolves mapping workbook path.

    Priority:
      1) explicit second argument
         - absolute path -> used directly
         - relative path -> resolved relative to cwd, then root_folder
      2) auto-detect first suitable .xlsx in root_folder, excluding generated outputs
    """
    if arg_path:
        candidates = []
        if os.path.isabs(arg_path):
            candidates.append(arg_path)
        else:
            candidates.append(arg_path)
            candidates.append(os.path.join(root_folder, arg_path))

        for p in candidates:
            if os.path.isfile(p) and p.lower().endswith(".xlsx"):
                return p

        log_line(f"[!] Provided group mapping file not found or not .xlsx: {arg_path}", log_fp)
        return None

    auto_candidates = []
    for p in sorted(glob.glob(os.path.join(root_folder, "*.xlsx"))):
        base = os.path.basename(p).lower()
        if base == "diff.xlsx":
            continue
        if re.match(r"findings_all_\d{6}_\d{4}\.xlsx$", base):
            continue
        if base.startswith("~$"):
            continue
        auto_candidates.append(p)

    if auto_candidates:
        chosen = auto_candidates[0]
        log_line(f"[*] Auto-detected group mapping workbook: {chosen}", log_fp)
        return chosen

    return None

def load_group_map(groups_path: Optional[str], log_fp=None) -> Dict[str, str]:
    """
    Loads mapping from an Excel file where:
      - each column header is the group name
      - each non-empty cell under that column is a domain in that group

    Returns:
      normalized_domain -> group_name
    """
    group_map: Dict[str, str] = {}
    if not groups_path:
        log_line("[*] No group mapping workbook provided/found. Group columns will remain empty.", log_fp)
        return group_map

    if not os.path.isfile(groups_path):
        log_line(f"[!] Group mapping workbook not found, ignoring: {groups_path}", log_fp)
        return group_map

    try:
        df = pd.read_excel(groups_path, dtype=str)
    except Exception as e:
        log_line(f"[!] Failed to read group mapping workbook '{groups_path}': {e}", log_fp)
        return group_map

    if len(df.columns) == 0:
        log_line(f"[!] Group mapping workbook has no columns: {groups_path}", log_fp)
        return group_map

    loaded_groups = 0
    loaded_domains = 0

    for col in df.columns:
        group_name = str(col).strip()
        if not group_name:
            continue

        loaded_groups += 1
        series = df[col]

        for cell in series.dropna():
            raw = str(cell).strip()
            if not raw:
                continue

            norm = normalize_domain_key(raw)
            if not norm:
                continue

            group_map[norm] = group_name
            loaded_domains += 1

            if norm.startswith("www."):
                no_www = norm[4:]
                if no_www and no_www not in group_map:
                    group_map[no_www] = group_name

    log_line(f"[*] Loaded groups mapping from Excel: {loaded_groups} groups, {loaded_domains} domain entries", log_fp)
    return group_map

def group_for_domain(domain: str, group_map: Dict[str, str]) -> str:
    """
    Match order:
      - exact normalized
      - www/non-www variation
      - subdomain suffixes down to 2-label domain (e.g., example.aaa.pl -> aaa.pl)
    Chooses the first (most specific) match.
    """
    if not group_map:
        return ""

    for candidate in domain_candidate_keys(domain):
        if candidate in group_map:
            return group_map[candidate]

    return ""

def groups_for_domain_csv(domains_csv: str, group_map: Dict[str, str]) -> str:
    if not group_map:
        return ""
    groups: Set[str] = set()
    for part in str(domains_csv).split(","):
        d = part.strip()
        if not d:
            continue
        g = group_for_domain(d, group_map)
        if g:
            groups.add(g)
    return ", ".join(sorted(groups))

# ---------------------------------------------------------------------------
# HTML parsing (CVE-only)
# ---------------------------------------------------------------------------

IP_DOMAIN_REGEX = re.compile(r"IP:\s*([\d\.]+)\s*\(([^)]+)\)")
CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}")

def extract_ip_domain(text: str) -> Optional[Tuple[str, str]]:
    m = IP_DOMAIN_REGEX.search(text)
    return (m.group(1), m.group(2)) if m else None

def extract_cves(text: str) -> List[str]:
    return sorted(set(CVE_REGEX.findall(text)))

def parse_html_reports(folder: str) -> List[Dict[str, str]]:
    print(f"[*] Parsing HTML reports in: {folder}")
    records: List[Dict[str, str]] = []
    html_files = [
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.lower().endswith(".html")
    ]

    for html_path in sorted(html_files):
        with open(html_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        ip_dom = extract_ip_domain(text)
        if not ip_dom:
            continue
        ip, domain = ip_dom

        for cve in extract_cves(text):
            records.append({"ip": ip, "domain": domain, "cve": cve})

    print(f"[*] Found {len(records)} CVE/IP/domain records in {folder}")
    return records

# ---------------------------------------------------------------------------
# Config checks
# ---------------------------------------------------------------------------

def extract_config_issues(folder: str, group_map: Dict[str, str]) -> List[Dict[str, str]]:
    print(f"[*] Extracting configuration issues in: {folder}")

    html_files = [
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.lower().endswith(".html")
    ]

    desc_to_domains: Dict[str, set] = {c["name"]: set() for c in CONFIG_CHECKS}

    for html_path in sorted(html_files):
        with open(html_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        base, _ = os.path.splitext(os.path.basename(html_path))
        for c in CONFIG_CHECKS:
            if re.search(c["pattern"], text):
                desc_to_domains[c["name"]].add(base)

    rows: List[Dict[str, str]] = []
    for desc, domains in desc_to_domains.items():
        if domains:
            domains_csv = ", ".join(sorted(domains))
            rows.append({
                "Description": desc,
                "Count": len(domains),
                "Domains": domains_csv,
                "Group": groups_for_domain_csv(domains_csv, group_map),
            })

    print(f"[*] Found {len(rows)} config issue types in {folder}")
    return rows

# ---------------------------------------------------------------------------
# Folder processing (CVE-only)
# ---------------------------------------------------------------------------

def process_folder(folder: str, log_fp, group_map: Dict[str, str]):
    log_line(f"\n=== Processing folder: {folder} ===", log_fp)

    records = parse_html_reports(folder)
    if not records:
        log_line(f"[!] No CVE/IP/domain records in {folder}, skipping.", log_fp)
        return None

    detail_rows = []
    for r in records:
        detail_rows.append({
            "CVE": r["cve"],
            "IP": r["ip"],
            "Domain": r["domain"],
            "Group": group_for_domain(r["domain"], group_map),
        })
    detail_df = pd.DataFrame(detail_rows)

    unique_cves = sorted(set(detail_df["CVE"].astype(str).tolist()))

    grouped = detail_df.groupby(["CVE"], dropna=False)
    agg_rows: List[Dict[str, str]] = []
    for (cve,), group in grouped:
        domains = sorted(set(group["Domain"].astype(str).tolist()))
        ips = sorted(set(group["IP"].astype(str).tolist()))
        groups = sorted({g for g in group["Group"].astype(str).tolist() if g})

        agg_rows.append({
            "CVE": cve,
            "Statistics": len(group),
            "Domains": ", ".join(domains),
            "Group": ", ".join(groups),
            "IP": ", ".join(ips),
        })
    agg_df = pd.DataFrame(sorted(agg_rows, key=lambda r: r["Statistics"], reverse=True))

    config_rows = extract_config_issues(folder, group_map)
    config_df = pd.DataFrame(config_rows) if config_rows else pd.DataFrame(
        columns=["Description", "Count", "Domains", "Group"]
    )

    folder_name = os.path.basename(os.path.normpath(folder))

    config_issue_types = int(len(config_df)) if not config_df.empty else 0
    config_total_findings = int(config_df["Count"].sum()) if (not config_df.empty and "Count" in config_df.columns) else 0

    log_line("\n--- Folder summary ---", log_fp)
    log_line(f"[+] Folder: {folder_name}", log_fp)
    log_line(f"[+] CVE rows (CVE occurrences across HTMLs): {len(detail_df)}", log_fp)
    log_line(f"[+] Unique CVEs: {len(unique_cves)}", log_fp)
    log_line(f"[+] Config issue types: {config_issue_types}", log_fp)
    log_line(f"[+] Config total findings (sum of counts): {config_total_findings}", log_fp)

    return folder_name, detail_df, agg_df, config_df

# ---------------------------------------------------------------------------
# Combined workbook helpers
# ---------------------------------------------------------------------------

def safe_sheet_name(base: str, suffix: str) -> str:
    name = f"{base}_{suffix}"
    if len(name) <= 31:
        return name
    extra = len(name) - 31
    base_trunc = base[:-extra] if extra < len(base) else base[:15]
    return f"{base_trunc}_{suffix}"[:31]

def build_all_data_frames(
    results: List[Tuple[str, pd.DataFrame, pd.DataFrame, pd.DataFrame]]
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    detailed_frames: List[pd.DataFrame] = []
    stats_frames: List[pd.DataFrame] = []
    config_frames: List[pd.DataFrame] = []

    for folder_name, detail_df, agg_df, config_df in results:
        if detail_df is not None and not detail_df.empty:
            d = detail_df.copy()
            d.insert(0, "Folder", folder_name.upper())
            cols = ["Folder", "CVE", "IP", "Domain", "Group"]
            d = d[[c for c in cols if c in d.columns]]
            detailed_frames.append(d)

        if agg_df is not None and not agg_df.empty:
            s = agg_df.copy()
            s.insert(0, "Folder", folder_name.upper())
            cols = ["Folder", "CVE", "Statistics", "Domains", "Group", "IP"]
            s = s[[c for c in cols if c in s.columns]]
            stats_frames.append(s)

        if config_df is not None and not config_df.empty:
            c = config_df.copy()
            c.insert(0, "Folder", folder_name.upper())
            cols = ["Folder", "Description", "Count", "Domains", "Group"]
            c = c[[col for col in cols if col in c.columns]]
            config_frames.append(c)

    all_detailed_df = (
        pd.concat(detailed_frames, ignore_index=True)
        if detailed_frames else pd.DataFrame(columns=["Folder", "CVE", "IP", "Domain", "Group"])
    )
    all_stats_df = (
        pd.concat(stats_frames, ignore_index=True)
        if stats_frames else pd.DataFrame(columns=["Folder", "CVE", "Statistics", "Domains", "Group", "IP"])
    )
    all_config_df = (
        pd.concat(config_frames, ignore_index=True)
        if config_frames else pd.DataFrame(columns=["Folder", "Description", "Count", "Domains", "Group"])
    )

    if not all_detailed_df.empty and "CVE" in all_detailed_df.columns:
        all_detailed_df = all_detailed_df.sort_values(
            ["Folder", "CVE", "Domain", "IP"], kind="stable"
        ).reset_index(drop=True)

    if not all_stats_df.empty:
        if "Statistics" in all_stats_df.columns:
            all_stats_df = all_stats_df.sort_values(
                ["Statistics", "Folder", "CVE"], ascending=[False, True, True], kind="stable"
            ).reset_index(drop=True)
        else:
            all_stats_df = all_stats_df.sort_values(["Folder", "CVE"], kind="stable").reset_index(drop=True)

    if not all_config_df.empty:
        sort_cols = [c for c in ["Description", "Count", "Folder"] if c in all_config_df.columns]
        ascending = [True, False, True][: len(sort_cols)]
        all_config_df = all_config_df.sort_values(sort_cols, ascending=ascending, kind="stable").reset_index(drop=True)

    return all_detailed_df, all_stats_df, all_config_df

def build_konfiguracyjne_all_aggregated(
    results: List[Tuple[str, pd.DataFrame, pd.DataFrame, pd.DataFrame]],
    group_map: Dict[str, str],
) -> pd.DataFrame:
    frames: List[pd.DataFrame] = []

    for folder_name, detail_df, agg_df, config_df in results:
        if config_df is None or config_df.empty:
            continue

        df = config_df.copy()

        if "Description" not in df.columns:
            continue
        if "Count" not in df.columns:
            df["Count"] = 0
        if "Domains" not in df.columns:
            df["Domains"] = ""

        df["Description"] = df["Description"].astype(str)
        df["Count"] = pd.to_numeric(df["Count"], errors="coerce").fillna(0).astype(int)
        df["Domains"] = df["Domains"].fillna("").astype(str)

        frames.append(df[["Description", "Count", "Domains"]])

    if not frames:
        return pd.DataFrame(columns=["Description", "Count", "Domains", "Group"])

    all_cfg = pd.concat(frames, ignore_index=True)

    def merge_domains(series: pd.Series) -> str:
        domains_set = set()
        for cell in series.dropna().astype(str):
            parts = [p.strip() for p in cell.split(",") if p.strip()]
            domains_set.update(parts)
        return ", ".join(sorted(domains_set))

    grouped = (
        all_cfg.groupby("Description", dropna=False, as_index=False)
        .agg(
            Count=("Count", "sum"),
            Domains=("Domains", merge_domains),
        )
    )

    grouped["Group"] = grouped["Domains"].apply(lambda x: groups_for_domain_csv(x, group_map))
    grouped = grouped[["Description", "Count", "Domains", "Group"]]
    grouped = grouped.sort_values(["Count", "Description"], ascending=[False, True], kind="stable").reset_index(drop=True)
    return grouped

# ---------------------------------------------------------------------------
# Diff loading helpers
# ---------------------------------------------------------------------------

def discover_existing_findings_all_in_root(root_folder: str, new_basename: str) -> Optional[str]:
    candidates = glob.glob(os.path.join(root_folder, "findings_all_*.xlsx"))
    candidates = [p for p in candidates if os.path.basename(p) != new_basename]
    if not candidates:
        return None
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]

def _normalize_str(val) -> str:
    if pd.isna(val):
        return ""
    return str(val).strip()

def _normalize_folder_name(name: str) -> str:
    return _normalize_str(name).upper()

def load_cve_state_from_combined(xlsx_path: str) -> Dict[str, Dict[Tuple[str, str], set]]:
    xls = pd.ExcelFile(xlsx_path)
    out: Dict[str, Dict[Tuple[str, str], set]] = {}

    if "All_data_detailed" in xls.sheet_names:
        df = pd.read_excel(xls, sheet_name="All_data_detailed")
        required = {"Folder", "CVE", "IP", "Domain"}
        if not df.empty and required.issubset(df.columns):
            for _, row in df.iterrows():
                folder = _normalize_folder_name(row["Folder"])
                cve = _normalize_str(row["CVE"])
                ip = _normalize_str(row["IP"])
                domain = _normalize_str(row["Domain"])

                if not folder or not cve:
                    continue

                out.setdefault(folder, {})
                out[folder].setdefault((domain, ip), set()).add(cve)
            return out

    for sheet in xls.sheet_names:
        if not sheet.endswith("_CVE_stats_detailed"):
            continue

        folder = _normalize_folder_name(sheet[: -len("_CVE_stats_detailed")])
        df = pd.read_excel(xls, sheet_name=sheet)

        required = {"CVE", "IP", "Domain"}
        if df.empty or not required.issubset(df.columns):
            continue

        out.setdefault(folder, {})
        for _, row in df.iterrows():
            cve = _normalize_str(row["CVE"])
            ip = _normalize_str(row["IP"])
            domain = _normalize_str(row["Domain"])
            if not cve:
                continue
            out[folder].setdefault((domain, ip), set()).add(cve)

    return out

def load_config_state_from_combined(xlsx_path: str) -> Dict[str, Dict[str, Dict[str, str]]]:
    """
    Returns:
      {
        FOLDER: {
          DESCRIPTION: {
            "Domains": "...",
            "Group": "..."
          }
        }
      }
    }
    """
    xls = pd.ExcelFile(xlsx_path)
    out: Dict[str, Dict[str, Dict[str, str]]] = {}

    for sheet in xls.sheet_names:
        if not sheet.endswith("_Config_Issues"):
            continue

        folder = _normalize_folder_name(sheet[: -len("_Config_Issues")])
        df = pd.read_excel(xls, sheet_name=sheet)

        if df.empty or "Description" not in df.columns:
            continue

        out.setdefault(folder, {})

        if "Domains" not in df.columns:
            df["Domains"] = ""
        if "Group" not in df.columns:
            df["Group"] = ""

        for _, row in df.iterrows():
            desc = _normalize_str(row["Description"])
            if not desc:
                continue

            out[folder][desc] = {
                "Domains": _normalize_str(row["Domains"]),
                "Group": _normalize_str(row["Group"]),
            }

    return out

# ---------------------------------------------------------------------------
# Diff building
# ---------------------------------------------------------------------------

def build_diff_artifacts(prev_path: str, new_path: str, group_map: Dict[str, str]):
    prev_cve = load_cve_state_from_combined(prev_path)
    cur_cve = load_cve_state_from_combined(new_path)

    prev_cfg = load_config_state_from_combined(prev_path)
    cur_cfg = load_config_state_from_combined(new_path)

    folders = sorted(set(prev_cve.keys()) | set(cur_cve.keys()) | set(prev_cfg.keys()) | set(cur_cfg.keys()))

    def fmt(items: List[str], limit: int = 100) -> str:
        if not items:
            return "none"
        if len(items) <= limit:
            return ", ".join(items)
        return ", ".join(items[:limit]) + f" ... (+{len(items) - limit})"

    lines: List[str] = []
    lines.append("diff.txt - findings_all comparison")
    lines.append(f"Previous: {os.path.basename(prev_path)}")
    lines.append(f"New:      {os.path.basename(new_path)}")
    lines.append("")

    cve_folder_rows: List[Dict[str, object]] = []
    config_rows: List[Dict[str, object]] = []

    total = {
        "new_cves_folder_unique": 0,
        "rem_cves_folder_unique": 0,
        "unchanged_cves_folder_unique": 0,
        "new_cve_assignments": 0,
        "rem_cve_assignments": 0,
        "unchanged_cve_assignments": 0,
        "new_cfg": 0,
        "rem_cfg": 0,
        "unchanged_cfg": 0,
    }

    any_rows_for_txt = False

    for f in folders:
        p_folder = prev_cve.get(f, {})
        c_folder = cur_cve.get(f, {})

        p_cfg_map = prev_cfg.get(f, {})
        c_cfg_map = cur_cfg.get(f, {})

        p_all_cves = set()
        for cve_set in p_folder.values():
            p_all_cves.update(cve_set)

        c_all_cves = set()
        for cve_set in c_folder.values():
            c_all_cves.update(cve_set)

        new_cves_folder = sorted(c_all_cves - p_all_cves)
        rem_cves_folder = sorted(p_all_cves - c_all_cves)
        unchanged_cves_folder = sorted(c_all_cves & p_all_cves)

        domain_ip_keys = sorted(set(p_folder.keys()) | set(c_folder.keys()))

        added_assignments = 0
        removed_assignments = 0
        unchanged_assignments = 0

        for key in domain_ip_keys:
            prev_set = p_folder.get(key, set())
            cur_set = c_folder.get(key, set())

            added = sorted(cur_set - prev_set)
            removed = sorted(prev_set - cur_set)
            unchanged = sorted(prev_set & cur_set)

            domain, ip = key
            domain_val = domain if domain else ""
            ip_val = ip if ip else ""
            group_val = group_for_domain(domain_val, group_map)

            added_assignments += len(added)
            removed_assignments += len(removed)
            unchanged_assignments += len(unchanged)

            for cve in added:
                cve_folder_rows.append({
                    "Folder": f,
                    "CVE": cve,
                    "Domain": domain_val,
                    "Group": group_val,
                    "IP": ip_val,
                    "Status Podatnosci": STATUS_ADDED,
                })

            for cve in removed:
                cve_folder_rows.append({
                    "Folder": f,
                    "CVE": cve,
                    "Domain": domain_val,
                    "Group": group_val,
                    "IP": ip_val,
                    "Status Podatnosci": STATUS_REMOVED,
                })

            for cve in unchanged:
                cve_folder_rows.append({
                    "Folder": f,
                    "CVE": cve,
                    "Domain": domain_val,
                    "Group": group_val,
                    "IP": ip_val,
                    "Status Podatnosci": STATUS_UNCHANGED,
                })

        prev_cfg_set = set(p_cfg_map.keys())
        cur_cfg_set = set(c_cfg_map.keys())

        new_cfg = sorted(cur_cfg_set - prev_cfg_set)
        rem_cfg = sorted(prev_cfg_set - cur_cfg_set)
        unchanged_cfg = sorted(cur_cfg_set & prev_cfg_set)

        for item in new_cfg:
            meta = c_cfg_map.get(item, {})
            config_rows.append({
                "Folder": f,
                "Description": item,
                "Domains": meta.get("Domains", ""),
                "Group": meta.get("Group", ""),
                "Status Podatnosci": STATUS_ADDED,
            })

        for item in rem_cfg:
            meta = p_cfg_map.get(item, {})
            config_rows.append({
                "Folder": f,
                "Description": item,
                "Domains": meta.get("Domains", ""),
                "Group": meta.get("Group", ""),
                "Status Podatnosci": STATUS_REMOVED,
            })

        for item in unchanged_cfg:
            meta = c_cfg_map.get(item, {}) or p_cfg_map.get(item, {})
            config_rows.append({
                "Folder": f,
                "Description": item,
                "Domains": meta.get("Domains", ""),
                "Group": meta.get("Group", ""),
                "Status Podatnosci": STATUS_UNCHANGED,
            })

        has_any = bool(
            new_cves_folder or rem_cves_folder or unchanged_cves_folder or
            new_cfg or rem_cfg or unchanged_cfg
        )
        if not has_any:
            continue

        any_rows_for_txt = True
        lines.append(f"Folder: {f}")
        lines.append(f"  New CVEs in folder ({len(new_cves_folder)}): {fmt(new_cves_folder)}")
        lines.append(f"  Removed CVEs in folder ({len(rem_cves_folder)}): {fmt(rem_cves_folder)}")
        lines.append(f"  Unchanged CVEs in folder ({len(unchanged_cves_folder)}): {fmt(unchanged_cves_folder)}")

        lines.append(f"  New config issues ({len(new_cfg)}):")
        for item in new_cfg:
            meta = c_cfg_map.get(item, {})
            domains_txt = meta.get("Domains", "")
            lines.append(f"    - {item}" + (f" | Domains: {domains_txt}" if domains_txt else ""))

        lines.append(f"  Removed config issues ({len(rem_cfg)}):")
        for item in rem_cfg:
            meta = p_cfg_map.get(item, {})
            domains_txt = meta.get("Domains", "")
            lines.append(f"    - {item}" + (f" | Domains: {domains_txt}" if domains_txt else ""))

        lines.append(f"  Unchanged config issues ({len(unchanged_cfg)}):")
        for item in unchanged_cfg:
            meta = c_cfg_map.get(item, {}) or p_cfg_map.get(item, {})
            domains_txt = meta.get("Domains", "")
            lines.append(f"    - {item}" + (f" | Domains: {domains_txt}" if domains_txt else ""))

        lines.append("")

        total["new_cves_folder_unique"] += len(new_cves_folder)
        total["rem_cves_folder_unique"] += len(rem_cves_folder)
        total["unchanged_cves_folder_unique"] += len(unchanged_cves_folder)
        total["new_cve_assignments"] += added_assignments
        total["rem_cve_assignments"] += removed_assignments
        total["unchanged_cve_assignments"] += unchanged_assignments
        total["new_cfg"] += len(new_cfg)
        total["rem_cfg"] += len(rem_cfg)
        total["unchanged_cfg"] += len(unchanged_cfg)

    if not any_rows_for_txt:
        lines.append("No differences found.")
        lines.append("No unchanged items found either.")
        lines.append("")

    lines.append("Totals (sum across folders with data):")
    lines.append(f"  New CVEs in folders (unique-per-folder): {total['new_cves_folder_unique']}")
    lines.append(f"  Removed CVEs in folders (unique-per-folder): {total['rem_cves_folder_unique']}")
    lines.append(f"  Unchanged CVEs in folders (unique-per-folder): {total['unchanged_cves_folder_unique']}")
    lines.append(f"  Added CVE assignments (Domain/IP-level): {total['new_cve_assignments']}")
    lines.append(f"  Removed CVE assignments (Domain/IP-level): {total['rem_cve_assignments']}")
    lines.append(f"  Unchanged CVE assignments (Domain/IP-level): {total['unchanged_cve_assignments']}")
    lines.append(f"  New config issues: {total['new_cfg']}")
    lines.append(f"  Removed config issues: {total['rem_cfg']}")
    lines.append(f"  Unchanged config issues: {total['unchanged_cfg']}")

    cve_folder_df = pd.DataFrame(cve_folder_rows) if cve_folder_rows else pd.DataFrame(columns=[
        "Folder", "CVE", "Domain", "Group", "IP", "Status Podatnosci"
    ])

    config_df = pd.DataFrame(config_rows) if config_rows else pd.DataFrame(columns=[
        "Folder", "Description", "Domains", "Group", "Status Podatnosci"
    ])

    if not cve_folder_df.empty:
        cve_folder_df = cve_folder_df.sort_values(
            ["Folder", "Status Podatnosci", "Domain", "IP", "CVE"],
            kind="stable"
        ).reset_index(drop=True)
        cve_folder_df = cve_folder_df[
            ["Folder", "CVE", "Domain", "Group", "IP", "Status Podatnosci"]
        ]

    if not config_df.empty:
        config_df = config_df.sort_values(
            ["Folder", "Status Podatnosci", "Description"],
            kind="stable"
        ).reset_index(drop=True)
        config_df = config_df[
            ["Folder", "Description", "Domains", "Group", "Status Podatnosci"]
        ]

    return lines, cve_folder_df, config_df

def write_diff_txt_and_excel(prev_path: str, new_path: str, out_txt: str, out_xlsx: str, group_map: Dict[str, str]) -> None:
    lines, cve_folder_df, config_df = build_diff_artifacts(prev_path, new_path, group_map)

    with open(out_txt, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))

    with pd.ExcelWriter(out_xlsx, engine="openpyxl") as writer:
        cve_folder_df.to_excel(writer, sheet_name="CVE_Folder_Changes", index=False)
        config_df.to_excel(writer, sheet_name="Config_Changes", index=False)

def write_no_previous_diff_txt_and_excel(
    prev_path_root: Optional[str],
    new_path_root: str,
    diff_txt: str,
    diff_xlsx: str,
) -> None:
    with open(diff_txt, "w", encoding="utf-8") as fp:
        fp.write(
            "diff.txt - findings_all comparison\n"
            f"Previous: {os.path.basename(prev_path_root) if prev_path_root else 'none found in root'}\n"
            f"New:      {os.path.basename(new_path_root)}\n\n"
            "No comparison performed because a previous findings_all_*.xlsx was not found in the root folder.\n"
        )

    empty_cve_folder_df = pd.DataFrame(columns=[
        "Folder", "CVE", "Domain", "Group", "IP", "Status Podatnosci"
    ])
    empty_config_df = pd.DataFrame(columns=[
        "Folder", "Description", "Domains", "Group", "Status Podatnosci"
    ])

    with pd.ExcelWriter(diff_xlsx, engine="openpyxl") as writer:
        empty_cve_folder_df.to_excel(writer, sheet_name="CVE_Folder_Changes", index=False)
        empty_config_df.to_excel(writer, sheet_name="Config_Changes", index=False)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <root_folder_with_subfolders> [group_mapping_file.xlsx]")
        sys.exit(1)

    root_folder = sys.argv[1]
    mapping_arg = sys.argv[2] if len(sys.argv) >= 3 else None

    if not os.path.isdir(root_folder):
        print(f"[!] Not a directory: {root_folder}")
        sys.exit(1)

    excel_root = os.path.join(root_folder, "Excel")
    os.makedirs(excel_root, exist_ok=True)

    stamp = ts_suffix()
    run_log_path = os.path.join(excel_root, f"log_{stamp}.txt")

    with open(run_log_path, "w", encoding="utf-8") as log_fp:
        log_line(f"[*] Root: {root_folder}", log_fp)
        log_line(f"[*] Log file: {run_log_path}", log_fp)

        groups_file = resolve_group_mapping_path(root_folder, mapping_arg, log_fp)
        if groups_file:
            log_line(f"[*] Group mapping workbook: {groups_file}", log_fp)

        group_map = load_group_map(groups_file, log_fp)

        subfolders = sorted(
            d for d in os.listdir(root_folder)
            if os.path.isdir(os.path.join(root_folder, d)) and d != "Excel"
        )

        known_set = set(KNOWN_SUBFOLDERS)
        ordered = [d for d in KNOWN_SUBFOLDERS if d in subfolders] + [d for d in subfolders if d not in known_set]

        results = []
        for sub in ordered:
            res = process_folder(os.path.join(root_folder, sub), log_fp, group_map)
            if res is not None:
                results.append(res)

        if not results:
            log_line("[!] No data from any subfolder. Exiting.", log_fp)
            return

        # Per-folder Excel files in <root>/Excel/
        for folder_name, detail_df, agg_df, config_df in results:
            per_path = os.path.join(excel_root, f"findings_{folder_name}_{stamp}.xlsx")
            with pd.ExcelWriter(per_path, engine="openpyxl") as writer:
                detail_df.to_excel(writer, sheet_name="CVE_stats_detailed", index=False)
                agg_df.to_excel(writer, sheet_name="CVE_stats", index=False)
                config_df.to_excel(writer, sheet_name="Config_Issues", index=False)

            log_line(f"[+] Wrote per-folder: {per_path}", log_fp)

        # Combined workbook ONLY in root
        new_basename = f"findings_all_{stamp}.xlsx"
        new_path_root = os.path.join(root_folder, new_basename)

        prev_path_root = discover_existing_findings_all_in_root(root_folder, new_basename)
        if prev_path_root:
            log_line(f"[*] Previous findings_all (root): {prev_path_root}", log_fp)
        else:
            log_line("[*] No previous findings_all_*.xlsx found in root. diff files will explain this.", log_fp)

        all_detailed_df, all_stats_df, all_config_df = build_all_data_frames(results)
        konfig_all_agg_df = build_konfiguracyjne_all_aggregated(results, group_map)

        with pd.ExcelWriter(new_path_root, engine="openpyxl") as writer:
            for folder_name, detail_df, agg_df, config_df in results:
                sheet_detailed = safe_sheet_name(folder_name, "CVE_stats_detailed")
                sheet_stats = safe_sheet_name(folder_name, "CVE_stats")
                sheet_config = safe_sheet_name(folder_name, "Config_Issues")

                detail_df.to_excel(writer, sheet_name=sheet_detailed, index=False)
                agg_df.to_excel(writer, sheet_name=sheet_stats, index=False)
                config_df.to_excel(writer, sheet_name=sheet_config, index=False)

            all_detailed_df.to_excel(writer, sheet_name="All_data_detailed", index=False)
            all_stats_df.to_excel(writer, sheet_name="All_data", index=False)
            konfig_all_agg_df.to_excel(writer, sheet_name="Konfiguracyjne_all", index=False)

        log_line(f"[+] Wrote NEW combined workbook (root only): {new_path_root}", log_fp)

        # Diff outputs in root
        diff_txt_path = os.path.join(root_folder, "diff.txt")
        diff_xlsx_path = os.path.join(root_folder, "diff.xlsx")

        if prev_path_root and os.path.isfile(new_path_root):
            try:
                write_diff_txt_and_excel(prev_path_root, new_path_root, diff_txt_path, diff_xlsx_path, group_map)
                log_line(f"[+] Wrote diff text report: {diff_txt_path}", log_fp)
                log_line(f"[+] Wrote diff Excel report: {diff_xlsx_path}", log_fp)
            except Exception as e:
                log_line(f"[!] Failed to write diff reports: {e}", log_fp)
        else:
            write_no_previous_diff_txt_and_excel(prev_path_root, new_path_root, diff_txt_path, diff_xlsx_path)
            log_line(f"[+] Wrote diff text report (no previous file found): {diff_txt_path}", log_fp)
            log_line(f"[+] Wrote diff Excel report (no previous file found): {diff_xlsx_path}", log_fp)

        log_line("\nAll done.", log_fp)

if __name__ == "__main__":
    main()

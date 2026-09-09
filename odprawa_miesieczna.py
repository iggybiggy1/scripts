#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Artemis / Tenable ASM HTML/PDF -> Excel findings + diff + vulnerability history.

V7: strict PDF primary-finding parser; CVEs mentioned only in PDF descriptions do not create extra findings.

USAGE:
    python3 artemis_findings_excel_multi_xlsx_history.py \
        <html_reports> \
        <group_mapping_file.xlsx> \
        <pk_pw_pp_mapping.xlsx>

Arguments:
    1. html_reports
       Working folder containing the current HTML/PDF reports. HTML files may be
       directly in this folder and/or in subfolders.

       The same tree may contain MULTIPLE historical combined workbooks, e.g.:
           findings_all_310126_1200.xlsx
           findings_all_280226_1200.xlsx
           findings_all_310326_1200.xlsx
           findings_all_300426_1200.xlsx
           findings_all_310526_1200.xlsx
           findings_all_300626_1200.xlsx

       ALL valid historical findings_all_*.xlsx snapshots are discovered
       recursively and used for history/trend calculations. No historical
       workbook is dropped merely because another scan exists in the same month.

    2. group_mapping_file.xlsx
       Existing organisational/domain mapping workbook.

    3. pk_pw_pp_mapping.xlsx
       Dedicated presentation mapping workbook with columns:
           PK | PI | PP

Example:
    python3 artemis_findings_excel_multi_xlsx_history.py \
        html_reports domeny_przypisane.xlsx podmioty.xlsx


Expected layout:
    <root>/szpitale/*.html
    <root>/instytuty/*.html
    <root>/ron/*.html
    ...

Outputs:
    <root>/Excel/findings_<Folder>_<STAMP>.xlsx
    <root>/findings_all_<STAMP>.xlsx
    <root>/diff.txt
    <root>/diff.xlsx
    Combined workbook additionally contains TOP5_PK / TOP5_PI / TOP5_PP dashboards.
    <root>/Excel/prezentacja_szczegoly_PK_<STAMP>.csv
    <root>/Excel/prezentacja_szczegoly_PI_<STAMP>.csv

Important design decisions:
- Every CVE occurrence found in a report HTML is extracted with as much adjacent
  information as possible (domain, IP, services, description, recommendation,
  source file, raw fragment).
- Config_Issues / Config_Detailed contain ONLY non-CVE findings.
  Any block/line containing a CVE identifier is excluded from configuration data.
  Known Artemis/Nuclei non-CVE categories are normalized to stable names, while
  other non-CVE top-level finding blocks are preserved generically.
- Diff identity intentionally ignores IP for CVEs. A CVE on the same domain cannot
  be both "added" and "removed" just because an address changed.
- Configuration identity is Folder + Description + Domain.
- History is maintained per vulnerability identity with first seen, current streak,
  last seen, disappearance timestamp, consecutive months and total observations.
- PK/PI/PP presentation classification is loaded from the dedicated LAST XLSX argument.
"""

from __future__ import annotations

import glob
import hashlib
import html as html_lib
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set, Tuple

import pandas as pd
from bs4 import BeautifulSoup

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None
from openpyxl import load_workbook
from openpyxl.chart import LineChart, Reference
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KNOWN_SUBFOLDERS = ["szpitale", "instytuty", "ron", "szkoly", "reszta", "pgz", "muzea"]

STATUS_ADDED = "dodane"
STATUS_REMOVED = "usuniete"
STATUS_UNCHANGED = "bez zmiany"

STAMP_RE = re.compile(r"findings_all_(\d{6}_\d{4})\.xlsx$", re.I)
CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.I)
IP_HOST_RE = re.compile(r"IP:\s*((?:\d{1,3}\.){3}\d{1,3})\s*\(([^)]+)\)", re.I)
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
FQDN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Presentation/dashboard settings based on the EASM reporting layout:
# PK = podmioty kluczowe, PI = podmioty ważne, PP = pozostałe podmioty.
PRESENTATION_CLASSES = ["PK", "PI", "PP"]
TOP_N = 5
TREND_POINTS = None
DASHBOARD_HEADER_FILL = "1F4E78"
DASHBOARD_SUBHEADER_FILL = "D9E2F3"
DASHBOARD_BODY_FILL = "E7E6E6"
DASHBOARD_BORDER_COLOR = "A6A6A6"


# Known categories are used to make descriptions stable between months.
# Generic report blocks are still preserved even if no pattern below matches.
CONFIG_CHECKS = [
    ("Brak naglowkow bezpieczenstwa HTTP",
     r"(?:Brak\s+nagłówków\s+bezpieczeństwa|Brak\s+naglowkow\s+bezpieczenstwa|"
     r"Domeny\s+z\s+brakującymi\s+nagłówkami|Domeny\s+z\s+brakujacymi\s+naglowkami|"
     r"http-missing-security-headers|missing\s+security\s+headers?|"
     r"(?:Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|"
     r"Referrer-Policy|Permissions-Policy).{0,80}(?:missing|brak))"),

    ("Brak ustawienia ciasteczka SameSite",
     r"(?:"
     r"Brak\s+ustawienia\s+ciasteczka\s+SameSite|"
     r"Brak\s+ustawienia\s+polityki\s+SameSite|"
     r"Brak.{0,120}\bSameSite\b|"
     r"\bSameSite\b.{0,100}(?:brak|missing|not set|unset|nie ustawion)|"
     r"http-cookie-missing-samesite|cookie.{0,100}missing.{0,40}samesite|"
     r"missing.{0,60}samesite.{0,60}cookie"
     r")"),

    ("Zastosowanie niewystarczajaco silnego klucza w DKIM",
     r"DKIM z krótkim kluczem|DKIM z krotkim kluczem|DKIM.*(?:short|krótk|krotk)"),

    ("Google API Key (jawny klucz Google API)",
     r"(?:Google\s+API\s+Key|jawny\s+klucz\s+Google\s+API|AIza[0-9A-Za-z_-]{20,})"),

    ("Dostep do zmiennych srodowiskowych przez cgi-bin",
     r"cgi-bin/printenv\.pl|printenv\.pl"),

    ("Ujawnienie wrazliwych logow Roundcube",
     r"Roundcube log disclosure|Roundcube.*log"),

    ("Publicznie dostepne repozytorium / dane systemu kontroli wersji",
     r"Repozytorium Git dostepne publicznie|\.git/|version control system data|\bVCS\b"),

    ("Ujawnienie konfiguracji GitHub workflows",
     r"GitHub workflows disclosure|\.github/workflows"),

    ("Bledna konfiguracja narzedzia Behat",
     r"Behat config|behat\.yml"),

    ("Wykryto konfigurację serwerów pozwalającą na listing plików",
     r"(?:Wykryto\s+konfiguracj(?:ę|e)\s+serwer(?:ów|ow)\s+pozwalaj(?:ącą|aca)\s+na\s+listing\s+plik(?:ów|ow)|"
     r"konfiguracj(?:ę|e)\s+serwer(?:ów|ow)\s+pozwalaj(?:ącą|aca)\s+na\s+listing\s+plik(?:ów|ow)|"
     r"server(?:s)?\s+configuration.{0,120}(?:directory|file)\s+listing|"
     r"directory\s+listing\s+(?:is\s+)?enabled|autoindex\s+(?:is\s+)?enabled)"),

    ("Ujawnienie listy konfiguracji serwera",
     r"Pod (?:następującymi|poniższymi) adresami znajdują się pliki udostępniające informacje o konfiguracji serwera|"
     r"Pod (?:nastepujacymi|ponizszymi) adresami znajduja sie pliki udostepniajace informacje o konfiguracji serwera|"
     r"Configuration listing|server configuration disclosure|configuration disclosure|phpinfo|info\.php"),

    ("Wykrycie publicznego dostepu do phpinfo",
     r"Wykryto phpinfo|Wykryto stronę phpinfo|Wykryto strone phpinfo|phpinfo\(\)"),

    ("Otwarte porty bazy danych",
     r"(?:Następujące\s+serwery\s+mają\s+otwarty\s+port\s+bazy\s+danych|"
     r"Nastepujace\s+serwery\s+maja\s+otwarty\s+port\s+bazy\s+danych|"
     r"open\s+database\s+port|database.{0,120}(?:open|public|exposed).{0,60}port|"
     r"(?:mysql|mariadb|postgres(?:ql)?|mongodb|redis|mssql|oracle).{0,120}"
     r"(?:publicly accessible|exposed|open port))"),

    # IMPORTANT: WordPress and Joomla are intentionally separate.
    ("Nieaktualne wersje CMS/wtyczek",
     r"Pod (?:następującymi|poniższymi) adresami znajdują się strony z nieaktualnymi wtyczkami lub szablonami WordPress|"
     r"Pod (?:nastepujacymi|ponizszymi) adresami znajduja sie strony z nieaktualnymi wtyczkami lub szablonami WordPress|"
     r"nieaktualn(?:e|ymi).{0,100}(?:wtyczk|szablon).{0,100}WordPress|"
     r"outdated (?:wordpress )?(?:plugin|theme)|wp-content/(?:plugins|themes)/|"
     r"\bwtyczka\s+[a-z0-9_.-]+\s+w wersji\s+[0-9]|\bplugin\s+[a-z0-9_.-]+\s+(?:version|v)\s*[0-9]"),

    ("Nieaktualne wersje systemu Joomla",
     r"Pod (?:następującymi|poniższymi) adresami znajdują się nieaktualne wersje systemu Joomla|"
     r"Pod (?:nastepujacymi|ponizszymi) adresami znajduja sie nieaktualne wersje systemu Joomla|"
     r"nieaktualn(?:e|ymi).{0,100}wersj.{0,60}Joomla|old Joomla|outdated Joomla|"
     r"\bJoomla\s+\d+(?:\.\d+){1,3}\b"),

    ("Nieaktualne wersje CMS/wtyczek",
     r"Nieaktualne wersje CMS lub wtyczek|old Drupal|outdated Drupal|"
     r"przestarzał.{0,120}Drupal|przestarzal.{0,120}Drupal"),

    ("Brak przekierowania z HTTP na HTTPS",
     r"(?:"
     r"Następujące\s+adresy\s+nie\s+przekierowują\s+z\s+http://\s+na\s+https://|"
     r"Nastepujace\s+adresy\s+nie\s+przekierowuja\s+z\s+http://\s+na\s+https://|"
     r"nie\s+przekierowują\s+z\s+http://\s+na\s+https://|"
     r"nie\s+przekierowuja\s+z\s+http://\s+na\s+https://|"
     r"HTTP.{0,100}HTTPS.{0,100}redirect|"
     r"no\s+redirect.{0,100}https|"
     r"without\s+https\s+redirect"
     r")"),

    ("Problemy z konfiguracja TLS/SSL",
     r"Przestarzala wersja protokolu TLS|Przestarzała wersja protokolu TLS|"
     r"TLS\s*(?:1\.0|1\.1).{0,80}(?:deprecated|obsolete|przestarza)|"
     r"Certyfikat niepodpisany przez zaufany CA|"
     r"Certyfikaty SSL/TLS pod następującymi adresami nie są podpisane przez zaufane centrum certyfikacji|"
     r"Certyfikaty SSL/TLS pod nastepujacymi adresami nie sa podpisane przez zaufane centrum certyfikacji|"
     r"Certyfikaty SSL/TLS pod następującymi adresami wygasły|"
     r"Certyfikaty SSL/TLS pod nastepujacymi adresami wygasly|"
     r"Następujące adresy zwracają certyfikaty SSL/TLS wystawione na niepoprawne domeny|"
     r"Nastepujace adresy zwracaja certyfikaty SSL/TLS wystawione na niepoprawne domeny|"
     r"certyfikaty SSL/TLS wystawione na niepoprawne domeny|Problem z SSL/TLS|"
     r"Niezgodność nazwy hosta|Niezgodnosc nazwy hosta|"
     r"certificate.{0,80}(?:expired|invalid|hostname mismatch|untrusted|self[- ]signed)|"
     r"SSL certificate|untrusted-root-certificate|expired certificate|"
     r"Taka konfiguracja sprawi, że próba wejścia na adres wyświetli użytkownikowi ostrzeżenie o niepoprawnym certyfikacie|"
     r"Taka konfiguracja sprawi, ze proba wejscia na adres wyswietli uzytkownikowi ostrzezenie o niepoprawnym certyfikacie|"
     r"Rekomendujemy poprawną konfigurację SSL/TLS|Rekomendujemy poprawna konfiguracje SSL/TLS"),

    ("Udostepnienie uwierzytelniania NTLM",
     r"(?:"
     r"Poniższe\s+końcówki\s+udostępniają\s+uwierzytelnianie\s+NTLM\s+przez\s+HTTP(?:\(S\)|S)?|"
     r"Następujące\s+końcówki\s+udostępniają\s+uwierzytelnianie\s+NTLM\s+przez\s+HTTP(?:\(S\)|S)?|"
     r"Ponizsze\s+koncowki\s+udostepniaja\s+uwierzytelnianie\s+NTLM\s+przez\s+HTTP(?:\(S\)|S)?|"
     r"Nastepujace\s+koncowki\s+udostepniaja\s+uwierzytelnianie\s+NTLM\s+przez\s+HTTP(?:\(S\)|S)?|"
     r"udostępniają\s+uwierzytelnianie\s+NTLM|"
     r"udostepniaja\s+uwierzytelnianie\s+NTLM|"
     r"NTLM\s+przez\s+HTTP(?:\(S\)|S)?|"
     r"NTLM.{0,300}Active\s+Directory|"
     r"Active\s+Directory.{0,300}NTLM"
     r")"),

    ("Nieprawidlowa konfiguracja mechanizmow weryfikacji nadawcy wiadomosci e-mail (DMARC, SPF, DKIM)",
     r"\bDMARC\b|\bSPF\b|\bDKIM\b|mechanizmów bezpieczeństwa poczty|mechanizmow bezpieczenstwa poczty|"
     r"mechanizmów weryfikacji nadawcy|mechanizmow weryfikacji nadawcy|Polityka DMARC|"
     r"nie ustawiono odbiorcy raportów w polu ['\"]?rua|nie ustawiono odbiorcy raportow w polu ['\"]?rua|"
     r"Error when processing\s+[^:]+:\s*Rekord SPF|Problem z mechanizmem SPF|Rekord SPF|open relay"),

    ("Ryzyko przejecia domeny / dangling DNS",
     r"ryzyko przejęcia domen|ryzyko przejecia domen|dangling DNS|subdomain takeover"),

    ("Podatnosc SQL Injection", r"SQL Injection|\bSQLi\b"),
    ("Ekspozycja panelu administracyjnego / logowania",
     r"panel(?:e|u)? administracyjn|admin panel|exposed panel|PhpMyAdmin|Adminer"),
    ("Ujawnienie pliku .env / konfiguracji", r"\.env\b|debug\.env|config\.bak|backup.*config"),
    ("WordPress XML-RPC dostepny", r"xmlrpc\.php"),
    ("Enumeracja uzytkownikow WordPress", r"wp-json.*users|wp-user-enum|enumeration.*users"),
    ("Wykrycie formularza logowania do WordPressa", r"WordPress login|wp-login\.php"),
    ("Zezwolenie na logowanie anonimowe FTP", r"anonymous login|ftp-anonymous-login"),
]

CONFIG_CHECKS_COMPILED = [(name, re.compile(pat, re.I | re.S)) for name, pat in CONFIG_CHECKS]


CONFIG_GENERIC_NOISE_RE = re.compile(
    r"^(?:Ostrzeżenie|Ostrzezenie|Warning|Informacja|Information|Uwaga|Note|Błąd|Blad|Error|"
    r"Problem|Finding|Wynik|Result|Kluczowe artefakty bezpieczeństwa|"
    r"Kluczowe artefakty bezpieczenstwa)\s*:?\s*$",
    re.I,
)

def is_meaningless_config_label(text: str) -> bool:
    if not text:
        return True
    t = re.sub(r"\s+", " ", str(text)).strip(" :-\t")
    return bool(CONFIG_GENERIC_NOISE_RE.fullmatch(t))


CONFIG_HARD_EXCLUDE_RE = re.compile(
    r"(?:"
    r"^\s*open[ -]?redirect\s*[:.!-]?\s*$|"
    r"^\s*Prosimy\s+pami[eę]ta[cć],?\s+[zż]e\s+certyfikat\s+SSL\s+mo[zż]na\s+otrzyma[cć]\s+r[oó]wnie[zż]\s+za\s+darmo\s*[.!]?\s*$"
    r")",
    re.I,
)


def is_hard_excluded_config_text(text: str) -> bool:
    if not text:
        return False
    t = re.sub(r"\s+", " ", str(text)).strip()
    return bool(CONFIG_HARD_EXCLUDE_RE.fullmatch(t))


def strip_excluded_config_lines(text: str) -> str:
    """Remove informational/excluded lines without deleting a valid surrounding finding."""
    if not text:
        return ""
    kept = []
    for raw in str(text).splitlines():
        line = re.sub(r"\s+", " ", raw).strip()
        if is_hard_excluded_config_text(line):
            continue
        kept.append(raw)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip()



# These lines are explanatory/remediation prose. They may be included in Details,
# but must never become a standalone configuration category through generic fallback.
CONFIG_RECOMMENDATION_ONLY_RE = re.compile(
    r"^(?:"
    r"Taka konfiguracja sprawi|"
    r"Rekomendujemy|Rekomendowane działania|"
    r"Jeśli strona nie jest już używana|Jesli strona nie jest juz uzywana|"
    r"Wdrożenie mechanizmów|Wdrozenie mechanizmow|"
    r"Więcej informacji|Wiecej informacji|"
    r"Brak reakcji może|Brak reakcji moze|"
    r"Jeśli zaś jest używana|Jesli zas jest uzywana|"
    r"Prosimy pamiętać, że certyfikat SSL można otrzymać również za darmo|"
    r"Prosimy pamietac, ze certyfikat SSL mozna otrzymac rowniez za darmo"
    r")",
    re.I | re.S,
)


def canonical_config_description(description: str, details: str = "") -> str:
    """
    Normalize current and historical config labels to one stable category.

    Known patterns always win over free-text labels. This also collapses old
    accidental categories (e.g. a long TLS recommendation sentence) into the
    intended canonical bucket.
    """
    desc = re.sub(r"\s+", " ", str(description or "")).strip()
    det = re.sub(r"\s+", " ", str(details or "")).strip()
    blob = (desc + "\n" + det).strip()

    # Hard exclusions requested for reporting.
    if is_hard_excluded_config_text(desc):
        return ""

    # Historical/current WordPress wording must collapse into one bucket.
    if re.fullmatch(r"(?i)\s*Nieaktualne\s+wtyczki\s*/?\s*szablony\s+WordPress\s*", desc):
        return "Nieaktualne wersje CMS/wtyczek"
    if re.search(r"(?i)nieaktualn(?:e|ymi).{0,100}(?:wtyczk|szablon).{0,100}WordPress|outdated (?:wordpress )?(?:plugin|theme)|wp-content/(?:plugins|themes)/", blob):
        return "Nieaktualne wersje CMS/wtyczek"

    for name, pat in CONFIG_CHECKS_COMPILED:
        if pat.search(blob):
            return name

    # Never preserve a generic warning heading as a configuration category.
    # "Ostrzeżenie" is a section/header marker, not a vulnerability name.
    if re.fullmatch(r"(?i)\s*(?:ostrzeżenie|ostrzezenie|warning)\s*[:.!-]?\s*", desc):
        return ""

    return desc


def looks_like_recommendation_only(text: str) -> bool:
    if not text:
        return False
    t = re.sub(r"\s+", " ", str(text)).strip()
    return bool(CONFIG_RECOMMENDATION_ONLY_RE.search(t))

# Generic non-CVE entries are accepted into Config_* only when they clearly
# describe a configuration/exposure/control problem. This prevents CVE
# descriptions from leaking into Config_* after a previous stage removed the
# literal CVE identifier.
CONFIG_SIGNAL_RE = re.compile(
    r"(?:"
    r"\b(?:brak|brakuje|nie znaleziono|nieprawidłow|błędn|problem z|ostrzeżenie|"
    r"publicznie dostęp|dostępny publicznie|zewnętrzny dostęp|otwarty port|"
    r"nie przekierow|niezaufan|niepoprawn|wygasł|przestarzał|słab(?:y|a|e)|"
    r"krótk(?:i|a|ie)|anonimow|listing|enumerac|ujawnieni|ekspozycj|"
    r"ryzyko przejęcia|dangling|takeover)\b|"
    r"\b(?:missing|misconfigur|insecure|exposed|exposure|publicly accessible|"
    r"open port|open relay|anonymous login|directory listing|weak|short key|"
    r"invalid certificate|expired certificate|hostname mismatch|missing header|"
    r"security header|no redirect|without https|information disclosure)\b|"
    r"\b(?:DMARC|SPF|DKIM|SameSite|HSTS|Content-Security-Policy|"
    r"X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy|"
    r"TLS|SSL|phpinfo|WordPress|Joomla|Drupal|Active Directory|NTLM)\b"
    r")",
    re.I | re.S,
)

# Strong indicators that a line/block is a vulnerability description rather
# than a configuration issue. These are checked even when the literal CVE ID
# has already been removed by CVSS annotation/filtering.
CVSS_PREFIX_RE = re.compile(
    r"^\s*\((?:krytyczne|wysokie|średnie|srednie|niskie|critical|high|medium|low|brak_danych)"
    r"\s*,\s*(?:\d+(?:\.\d+)?|brak)\)\s*:\s*",
    re.I,
)
VULNERABILITY_PROSE_RE = re.compile(
    r"(?:"
    r"\b(?:allows?|allowing|could allow|may allow|can allow)\b.{0,120}"
    r"\b(?:attacker|attackers|remote|unauthenticated|authenticated|user)\b|"
    r"\b(?:remote code execution|arbitrary code execution|privilege escalation|"
    r"authentication bypass|path traversal|directory traversal|buffer overflow|"
    r"use-after-free|sql injection|cross-site scripting|xss|csrf|ssrf|"
    r"command injection|code injection|memory corruption|denial of service)\b|"
    r"\b(?:users? (?:are|is) recommended to upgrade|upgrade to version|"
    r"versions? .* (?:before|through|prior to|and earlier))\b|"
    r"\b(?:an issue was discovered|a vulnerability was found|a flaw was found|"
    r"a path handling issue|improper validation|out-of-bounds|race condition)\b"
    r")",
    re.I | re.S,
)


def looks_like_product_vulnerability_text(text: str) -> bool:
    """True for CVE/vulnerability prose even when CVE ID itself is absent."""
    if not text:
        return False
    t = re.sub(r"\s+", " ", str(text)).strip()
    if CVE_RE.search(t):
        return True
    if CVSS_PREFIX_RE.search(t):
        return True
    if VULNERABILITY_PROSE_RE.search(t):
        return True
    return False


def is_explicit_configuration_finding(text: str) -> bool:
    """Accept known config patterns or clear configuration/exposure wording."""
    if not text:
        return False
    if looks_like_product_vulnerability_text(text):
        return False
    for _name, _pat in CONFIG_CHECKS_COMPILED:
        if _pat.search(text):
            return True
    return bool(CONFIG_SIGNAL_RE.search(text))

BOILERPLATE_PATTERNS = [
    re.compile(r"^Szanowni Państwo", re.I),
    re.compile(r"w ramach analizy bezpieczeństwa teleinformatycznego", re.I),
    re.compile(r"Zalecamy przeprowadzić weryfikację, czy podobne problemy", re.I),
    re.compile(r"Jeżeli któreś z podatności nie dotyczą podmiotu", re.I),
    re.compile(r"Prosimy pamiętać, że skanowanie jest rozłożone w czasie", re.I),
    re.compile(r"Jednocześnie przypominamy o rekomendowanej formie komunikacji", re.I),
    re.compile(r"Więcej informacji o działaniu mechanizmów weryfikacji nadawcy", re.I),
    re.compile(r"^IP:\s*\d{1,3}(?:\.\d{1,3}){3}\s*\([^)]+\)\s*$", re.I),
    re.compile(r"^Widoczne serwisy\s*:", re.I),
    re.compile(r"^CVEs?\s*:", re.I),
    re.compile(r"^Kluczowe artefakty bezpieczeństwa\s*:", re.I),
    re.compile(r"^Kluczowe artefakty bezpieczenstwa\s*:", re.I),
]


# ---------------------------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------------------------

def log_line(msg: str, log_fp=None) -> None:
    print(msg)
    if log_fp:
        log_fp.write(msg + "\n")
        log_fp.flush()


def ts_suffix(dt: Optional[datetime] = None) -> str:
    return (dt or datetime.now()).strftime("%d%m%y_%H%M")


def iso_ts(dt: Optional[datetime] = None) -> str:
    return (dt or datetime.now()).replace(microsecond=0).isoformat(sep=" ")


def parse_workbook_timestamp(path: str) -> datetime:
    m = STAMP_RE.search(os.path.basename(path))
    if m:
        try:
            return datetime.strptime(m.group(1), "%d%m%y_%H%M")
        except ValueError:
            pass
    return datetime.fromtimestamp(os.path.getmtime(path))



def _is_valid_combined_findings_workbook(path: str) -> bool:
    """Return True only for a combined findings snapshot workbook."""
    if not path or not os.path.isfile(path):
        return False

    base = os.path.basename(path).lower()
    if base.startswith("~$") or base == "diff.xlsx":
        return False

    try:
        xls = pd.ExcelFile(path)
        sheets = set(xls.sheet_names)
    except Exception:
        return False

    if "All_data_detailed" not in sheets:
        return False

    if re.match(r"^findings_all_.*\.xlsx$", base, re.I):
        return True

    return bool(
        {"All_Config_Detailed", "Konfiguracyjne_all", "History"} & sheets
    )


def discover_snapshot_workbooks(
    reports_root: str,
    current_path: Optional[str] = None,
    log_fp=None,
) -> List[str]:
    """
    Recursively discover all valid historical/current combined findings
    workbooks below the first CLI argument and sort them chronologically.
    """
    root = os.path.abspath(reports_root)
    candidates: List[str] = []

    for pattern in ("**/findings_all_*.xlsx", "**/*.xlsx"):
        candidates.extend(
            glob.glob(os.path.join(root, pattern), recursive=True)
        )

    if current_path and os.path.isfile(current_path):
        candidates.append(os.path.abspath(current_path))

    seen: Set[str] = set()
    valid: List[Tuple[datetime, str]] = []
    current_abs = os.path.abspath(current_path) if current_path else None

    for p in candidates:
        p = os.path.abspath(p)
        if p in seen:
            continue
        seen.add(p)

        if current_abs and p == current_abs:
            try:
                ts = parse_workbook_timestamp(p)
            except Exception:
                ts = datetime.fromtimestamp(os.path.getmtime(p))
            valid.append((ts, p))
            continue

        if not _is_valid_combined_findings_workbook(p):
            continue

        try:
            ts = parse_workbook_timestamp(p)
        except Exception:
            ts = datetime.fromtimestamp(os.path.getmtime(p))
        valid.append((ts, p))

    valid.sort(key=lambda x: (x[0], x[1]))
    paths = [p for _, p in valid]

    if log_fp is not None:
        log_line(
            f"[*] Discovered combined findings snapshots: {len(paths)}",
            log_fp,
        )
        for p in paths:
            log_line(
                f"    - {parse_workbook_timestamp(p).strftime('%Y-%m-%d %H:%M')} | {p}",
                log_fp,
            )

    return paths


def _norm(v) -> str:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return ""
    return str(v).strip()


def stable_join(values: Iterable[str]) -> str:
    return ", ".join(sorted({str(v).strip() for v in values if str(v).strip()}))


def sha1_text(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="replace")).hexdigest()


def safe_sheet_name(base: str, suffix: str) -> str:
    name = f"{base}_{suffix}"
    if len(name) <= 31:
        return name
    digest = hashlib.sha1(name.encode()).hexdigest()[:5]
    keep = 31 - len(suffix) - len(digest) - 2
    return f"{base[:max(1, keep)]}_{digest}_{suffix}"[:31]


# ---------------------------------------------------------------------------
# Domain / group mapping
# ---------------------------------------------------------------------------

def normalize_domain_key(value: str) -> str:
    s = _norm(value).lower()
    if not s:
        return ""
    s = html_lib.unescape(s)
    s = re.sub(r"^https?://", "", s, flags=re.I)
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].rstrip(".")
    if ":" in s:
        h, p = s.rsplit(":", 1)
        if p.isdigit():
            s = h
    return s.strip(". ")


def domain_suffix_candidates(domain_norm: str) -> List[str]:
    parts = [p for p in domain_norm.split(".") if p]
    if len(parts) < 2:
        return [domain_norm] if domain_norm else []
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def domain_candidate_keys(value: str) -> List[str]:
    norm = normalize_domain_key(value)
    if not norm:
        return []
    forms = [norm]
    forms.append(norm[4:] if norm.startswith("www.") else "www." + norm)
    out, seen = [], set()
    for form in forms:
        for cand in domain_suffix_candidates(form):
            if cand and cand not in seen:
                seen.add(cand)
                out.append(cand)
    return out


def resolve_group_mapping_path(root_folder: str, arg_path: Optional[str], log_fp=None) -> Optional[str]:
    if arg_path:
        candidates = [arg_path] if os.path.isabs(arg_path) else [arg_path, os.path.join(root_folder, arg_path)]
        for p in candidates:
            if os.path.isfile(p) and p.lower().endswith(".xlsx"):
                return p
        log_line(f"[!] Group mapping workbook not found: {arg_path}", log_fp)
        return None

    for p in sorted(glob.glob(os.path.join(root_folder, "*.xlsx"))):
        b = os.path.basename(p).lower()
        if b == "diff.xlsx" or b.startswith("findings_all_") or b.startswith("~$"):
            continue
        return p
    return None


def load_group_map(path: Optional[str], log_fp=None) -> Dict[str, str]:
    if not path:
        log_line("[*] No group mapping workbook. Group columns will be empty.", log_fp)
        return {}
    try:
        df = pd.read_excel(path, dtype=str)
    except Exception as e:
        log_line(f"[!] Failed to read group mapping workbook: {e}", log_fp)
        return {}
    out: Dict[str, str] = {}
    for col in df.columns:
        group = _norm(col)
        if not group:
            continue
        for cell in df[col].dropna():
            d = normalize_domain_key(cell)
            if d:
                out[d] = group
                if d.startswith("www."):
                    out.setdefault(d[4:], group)
    log_line(f"[*] Loaded {len(out)} normalized domain->group mappings", log_fp)
    return out



def resolve_presentation_mapping_path(
    root_folder: str,
    arg_path: Optional[str],
    log_fp=None,
) -> Optional[str]:
    """Resolve the dedicated PK/PI/PP XLSX supplied as the LAST CLI argument."""
    if not arg_path:
        log_line("[*] No dedicated PK/PI/PP mapping argument provided.", log_fp)
        return None

    if str(arg_path).strip() == "-":
        log_line("[*] PK/PI/PP mapping explicitly disabled with '-'.", log_fp)
        return None

    candidates: List[str] = []
    if os.path.isabs(arg_path):
        candidates.append(arg_path)
    else:
        candidates.append(os.path.abspath(arg_path))
        candidates.append(os.path.join(root_folder, arg_path))

    seen: Set[str] = set()
    for candidate in candidates:
        candidate = os.path.abspath(candidate)
        if candidate in seen:
            continue
        seen.add(candidate)
        if os.path.isfile(candidate) and candidate.lower().endswith(".xlsx"):
            return candidate

    log_line(
        f"[!] Dedicated PK/PI/PP mapping workbook not found or not XLSX: {arg_path}",
        log_fp,
    )
    return None


def load_presentation_class_map(path: Optional[str], log_fp=None) -> Dict[str, str]:
    """
    Load the dedicated PK/PI/PP classification workbook.

    Expected layout:
        PK              PI              PP
        domena1.pl      domena2.pl      domena3.pl

    A domain can belong to only one class. On conflicting assignments the first
    assignment wins and the conflict is written to the log.
    """
    out: Dict[str, str] = {}
    if not path:
        return out

    if not os.path.isfile(path):
        log_line(f"[!] PK/PI/PP mapping workbook does not exist: {path}", log_fp)
        return out

    try:
        xls = pd.ExcelFile(path)
    except Exception as e:
        log_line(f"[!] Failed opening PK/PI/PP mapping workbook '{path}': {e}", log_fp)
        return out

    found_columns = False
    conflicts: List[Tuple[str, str, str]] = []

    for sheet in xls.sheet_names:
        try:
            df = pd.read_excel(xls, sheet_name=sheet, dtype=str)
        except Exception as e:
            log_line(f"[!] Failed reading PK/PI/PP sheet '{sheet}': {e}", log_fp)
            continue

        col_lookup = {str(c).strip().upper(): c for c in df.columns}
        present = [code for code in PRESENTATION_CLASSES if code in col_lookup]
        if not present:
            continue

        found_columns = True

        for code in PRESENTATION_CLASSES:
            if code not in col_lookup:
                continue

            original_col = col_lookup[code]
            for cell in df[original_col].dropna():
                raw = str(cell).strip()
                if not raw or raw.lower() in {"nan", "none"}:
                    continue

                domain = normalize_domain_key(raw)
                if not domain:
                    continue

                previous = out.get(domain)
                if previous and previous != code:
                    conflicts.append((domain, previous, code))
                    continue

                out[domain] = code

                if domain.startswith("www."):
                    no_www = domain[4:]
                    previous_no_www = out.get(no_www)
                    if previous_no_www and previous_no_www != code:
                        conflicts.append((no_www, previous_no_www, code))
                    else:
                        out.setdefault(no_www, code)

    if not found_columns:
        log_line(
            "[!] PK/PI/PP mapping workbook contains no columns named PK, PI or PP.",
            log_fp,
        )
        return {}

    counts = {code: 0 for code in PRESENTATION_CLASSES}
    for code in out.values():
        if code in counts:
            counts[code] += 1

    log_line(
        "[*] Loaded dedicated PK/PI/PP mapping: "
        f"{len(out)} normalized entries "
        f"(PK={counts['PK']}, PI={counts['PI']}, PP={counts['PP']})",
        log_fp,
    )

    if conflicts:
        log_line(
            f"[!] Found {len(conflicts)} conflicting PK/PI/PP assignments. "
            "The first assignment was kept.",
            log_fp,
        )
        for domain, first_class, rejected_class in conflicts[:20]:
            log_line(
                f"    [conflict] {domain}: kept {first_class}, ignored {rejected_class}",
                log_fp,
            )

    return out


def presentation_entity_for_domain(
    domain: str,
    class_map: Optional[Dict[str, str]] = None,
) -> str:
    """
    Return the MAIN ENTITY DOMAIN used by PK/PI/PP presentation reporting.

    The entity domain is the most-specific suffix which is explicitly present
    in the dedicated PK/PI/PP mapping workbook.

    Example mapping:
        PK
        bbb.pl

    Findings:
        bbb.pl
        aaa.bbb.pl
        www.bbb.pl
        x.y.bbb.pl

    All return:
        bbb.pl

    This is intentionally mapping-driven instead of relying on a generic
    public-suffix algorithm. The PK/PI/PP workbook is therefore the source of
    truth for what constitutes one reporting entity.
    """
    norm = normalize_domain_key(domain)
    if not norm:
        return ""

    if class_map:
        # domain_candidate_keys() is ordered most-specific -> less-specific.
        # Prefer exact/mapped entity names, but normalize www away for display.
        for candidate in domain_candidate_keys(norm):
            if candidate in class_map:
                entity = normalize_domain_key(candidate)
                if entity.startswith("www."):
                    entity = entity[4:]
                return entity

    # Fallback only when no dedicated mapping matches.
    # Keep the normalized source domain rather than guessing ownership.
    return norm[4:] if norm.startswith("www.") else norm


def presentation_class_for_domain(
    domain: str,
    group_value: str,
    class_map: Optional[Dict[str, str]] = None,
) -> str:
    """
    Resolve PK/PI/PP for presentation reporting.

    Priority:
      1. Dedicated Podmioty.xlsx mapping (exact domain or parent/main domain).
      2. Explicit PK/PI/PP token in the organisational Group value.
      3. PP fallback.

    The PP fallback is intentional and important:
      PP = "pozostałe podmioty".
    A finding that is in the current scan scope must NEVER silently disappear
    from all three presentation classes merely because its domain was absent
    from Podmioty.xlsx.

    Therefore every valid CVE/config finding is assigned to exactly one of:
        PK, PI, PP
    """
    norm = normalize_domain_key(domain)

    if class_map and norm:
        entity = presentation_entity_for_domain(norm, class_map)

        if entity:
            if entity in class_map:
                return class_map[entity]

            www_entity = "www." + entity
            if www_entity in class_map:
                return class_map[www_entity]

        for candidate in domain_candidate_keys(norm):
            if candidate in class_map:
                return class_map[candidate]

    explicit_group_class = canonical_presentation_class(group_value)
    if explicit_group_class:
        return explicit_group_class

    # Fail-safe: every in-scope entity not explicitly PK/PI is PP.
    return "PP"


def group_for_domain(domain: str, group_map: Dict[str, str]) -> str:
    for cand in domain_candidate_keys(domain):
        if cand in group_map:
            return group_map[cand]
    return ""


def groups_for_domain_csv(domains_csv: str, group_map: Dict[str, str]) -> str:
    return stable_join(group_for_domain(x.strip(), group_map) for x in str(domains_csv).split(",") if x.strip())


# ---------------------------------------------------------------------------
# HTML normalization and extraction
# ---------------------------------------------------------------------------

def normalize_report_text(text: str) -> str:
    """
    Normalize text extracted from Artemis/Nuclei HTML/PDF reports.

    Handles common list/rendering variants:
      • CVE-2021-34798 ...
      · CVE-2021-34798 ...
      ‣ CVE-2021-34798 ...
      – CVE-2021-34798 ...
      CVE‑2021‑34798  (Unicode non-breaking hyphen)
      CVE–2021–34798  (en dash)

    CVE identifiers are normalized to the standard ASCII '-' representation
    before any CVE regex is evaluated.
    """
    if text is None:
        return ""

    text = html_lib.unescape(str(text))

    # Unicode spaces / zero-width characters.
    text = (
        text.replace("\u00a0", " ")
            .replace("\u2007", " ")
            .replace("\u202f", " ")
            .replace("\u200b", "")
            .replace("\ufeff", "")
    )

    # Normalize Unicode dash/hyphen characters globally. This is particularly
    # important for CVE IDs copied/rendered by office/web applications.
    for ch in ("\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2212"):
        text = text.replace(ch, "-")

    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Convert common visual list markers at the beginning of a line to plain
    # indentation. We do NOT remove characters inside normal prose.
    text = re.sub(
        r"(?m)^[ \t]*(?:[•·‣◦▪●○►▸➤➜]+\s*|[-*+]\s+)",
        "",
        text,
    )

    # A few HTML exports render ordered-list prefixes before CVEs, e.g.
    # "1. CVE-..." or "(1) CVE-...". Keep normal report section numbering but
    # remove the prefix only when it is immediately followed by a CVE.
    text = re.sub(
        r"(?mi)^[ \t]*(?:\(?\d{1,4}\)?[.)]\s+)(?=CVE-\d{4}-\d{4,7}\b)",
        "",
        text,
    )

    # Normalize spaces around separators inside CVE IDs.
    text = re.sub(
        r"(?i)\bCVE\s*-\s*(\d{4})\s*-\s*(\d{4,7})\b",
        lambda m: f"CVE-{m.group(1)}-{m.group(2)}",
        text,
    )

    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def read_pdf_text(path: str) -> str:
    """
    Extract text from a text-based PDF report.

    Uses pypdf. Scanned/image-only PDFs require OCR before running this script;
    the parser deliberately does not silently OCR because that would add a
    heavyweight and potentially inaccurate dependency to the reporting flow.
    """
    if PdfReader is None:
        raise RuntimeError(
            "PDF support requires pypdf. Install it with: pip install pypdf"
        )

    reader = PdfReader(path)
    pages = []

    for page_no, page in enumerate(reader.pages, start=1):
        try:
            txt = page.extract_text() or ""
        except Exception as exc:
            txt = ""
        if txt.strip():
            pages.append(txt)

    text = "\n".join(pages)
    return normalize_report_text(text)


def read_report(path: str) -> Tuple[Optional[BeautifulSoup], str, List[str]]:
    """
    Read either HTML/HTM or PDF and return:
        (BeautifulSoup-or-None, normalized_text, normalized_lines)

    Existing HTML parsing remains unchanged. PDF reports enter the same
    text-based CVE/configuration extraction pipeline.
    """
    ext = os.path.splitext(path)[1].lower()

    if ext in (".html", ".htm"):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()

        soup = BeautifulSoup(raw, "html.parser")
        visible = soup.get_text("\n", strip=True)
        text = normalize_report_text(visible)

    elif ext == ".pdf":
        soup = None
        text = read_pdf_text(path)

    else:
        raise ValueError(f"Unsupported report format: {path}")

    lines = [
        re.sub(
            r"^[ \t]*(?:[•·‣◦▪●○►▸➤➜]+\s*)",
            "",
            x,
        ).strip()
        for x in text.splitlines()
        if x.strip()
    ]

    return soup, text, lines


def read_html(path: str) -> Tuple[Optional[BeautifulSoup], str, List[str]]:
    """
    Backward-compatible name retained for the rest of the script.

    It now accepts HTML, HTM and PDF reports.
    """
    return read_report(path)


def is_boilerplate(block: str) -> bool:
    s = re.sub(r"\s+", " ", block).strip()
    if not s:
        return True
    return any(p.search(s) for p in BOILERPLATE_PATTERNS)


def extract_urls_domains_ips(block: str, default_domain: str) -> Tuple[str, str, str]:
    urls = [u.rstrip(".,;)") for u in URL_RE.findall(block)]
    ips = IP_RE.findall(block)
    domains = []
    for m in FQDN_RE.findall(block):
        d = normalize_domain_key(m)
        if d and not re.fullmatch(r"\d+(?:\.\d+){3}", d):
            domains.append(d)
    if default_domain:
        domains.append(default_domain)
    return stable_join(urls), stable_join(domains), stable_join(ips)



def strip_cve_content_from_block(block: str) -> str:
    """
    Return only the non-CVE portion of a mixed Artemis/Nuclei finding block.

    Rules:
    - every line containing CVE-YYYY-NNNN is removed;
    - a recommendation immediately following a removed CVE is removed;
    - CVE-only headings/containers are removed;
    - unrelated configuration lines in the same top-level HTML block are retained.

    Config_* sheets must never contain CVE data.
    """
    if not block:
        return ""

    lines = block.splitlines()
    kept: List[str] = []
    removed_cve_line = False

    cve_section_headers = re.compile(
        r"^\s*(?:CVEs?|CVE vulnerabilities?|Vulnerabilities?)\s*:?\s*$",
        re.I,
    )
    recommendation_re = re.compile(r"^\s*Rekomendacje?\s*:", re.I)

    for raw in lines:
        line = raw.strip()

        if not line:
            if kept and kept[-1] != "":
                kept.append("")
            continue

        if CVE_RE.search(line):
            removed_cve_line = True
            continue

        if cve_section_headers.match(line):
            removed_cve_line = True
            continue

        if removed_cve_line and recommendation_re.match(line):
            removed_cve_line = False
            continue

        removed_cve_line = False
        kept.append(raw)

    cleaned = "\n".join(kept)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    cleaned = "\n".join(
        ln for ln in cleaned.splitlines()
        if not CVE_RE.search(ln)
    ).strip()
    return cleaned


def config_record_is_strictly_non_cve(record: Dict[str, str]) -> bool:
    """Final guard used before Config_Detailed/Config_Issues/history/diff."""
    if not record:
        return False
    for field in ("Description", "Details", "URLs/Resources"):
        if CVE_RE.search(str(record.get(field, "") or "")):
            return False
    return True


def classify_config_description(block: str, domain: str) -> str:
    """
    Return a normalized CONFIG description.

    Rules:
    - CVE/product-vulnerability prose is never configuration.
    - Known configuration signatures are always mapped to canonical categories.
    - Explanatory/recommendation-only prose never becomes a standalone category.
    - Generic fallback is retained only for clear configuration/exposure findings.
    """
    if not block or looks_like_product_vulnerability_text(block):
        return ""

    block = strip_excluded_config_lines(block)
    if not block or is_hard_excluded_config_text(block):
        return ""

    if is_meaningless_config_label(block):
        return ""

    canonical = canonical_config_description("", block)
    if canonical:
        return canonical

    if looks_like_recommendation_only(block):
        return ""

    if not is_explicit_configuration_finding(block):
        return ""

    lines = [
        re.sub(r"\s+", " ", x).strip(" -•\t")
        for x in block.splitlines()
        if x.strip()
    ]
    title = ""

    for line in lines:
        if is_boilerplate(line):
            continue
        if is_meaningless_config_label(line):
            continue
        if looks_like_product_vulnerability_text(line):
            continue
        if looks_like_recommendation_only(line):
            continue
        if not is_explicit_configuration_finding(line):
            continue
        title = line
        break

    if not title:
        return ""

    # One more chance to normalize the selected title to a known bucket.
    canonical = canonical_config_description(title, block)
    if canonical != title:
        return canonical

    if domain:
        title = re.sub(re.escape(domain), "<domena>", title, flags=re.I)
    title = URL_RE.sub("<url>", title)
    title = IP_RE.sub("<ip>", title)
    title = re.sub(r"\s+", " ", title).strip(" :.-")
    return title[:240]

def top_level_li_blocks(soup: BeautifulSoup) -> List[str]:
    blocks: List[str] = []
    for li in soup.find_all("li"):
        if li.find_parent("li") is not None:
            continue
        txt = li.get_text("\n", strip=True)
        txt = html_lib.unescape(txt)
        txt = re.sub(r"[ \t]+", " ", txt)
        txt = re.sub(r"\n{3,}", "\n\n", txt).strip()
        if txt:
            blocks.append(txt)
    return blocks



def all_li_blocks(soup: BeautifulSoup) -> List[str]:
    """
    Return text from every LI element, including nested historical report lists.

    Historical Artemis/Tenable reports may place actual findings several levels
    below a top-level asset <li>. Config extraction therefore needs both
    top-level and nested list items.
    """
    blocks: List[str] = []
    seen: Set[str] = set()

    for li in soup.find_all("li"):
        txt = normalize_report_text(li.get_text("\n", strip=True))
        if not txt:
            continue

        # Exact normalized duplicates are common because parent LI contains
        # child LI text. Keep one copy.
        key = re.sub(r"\s+", " ", txt).strip().lower()
        if key in seen:
            continue
        seen.add(key)
        blocks.append(txt)

    return blocks


def fallback_finding_blocks(lines: List[str]) -> List[str]:
    """Best-effort blocks for report files that do not use <li> structure."""
    blocks: List[str] = []
    current: List[str] = []
    start_re = re.compile(
        r"^(?:\d+\.\s*)?(?:Następujące|Poniższe|Pod następującymi|Pod poniższymi|"
        r"Wykryto|Nie znaleziono|Polityka|Rekord|Problem|Ostrzeżenie|Certyfikat|Certyfikaty|"
        r"Brak |Domena |Przestarza|Publicznie|Zewnętrzny|Widoczny|Dostępny)", re.I
    )
    for line in lines:
        if start_re.search(line) and current:
            blocks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def normalize_severity(value: str) -> str:
    """Normalize Polish/English severity labels used by Artemis/Nuclei reports."""
    v = re.sub(r"\s+", " ", str(value or "")).strip().lower()
    mapping = {
        "krytyczne": "critical",
        "krytyczna": "critical",
        "krytyczny": "critical",
        "critical": "critical",
        "crit": "critical",
        "wysokie": "high",
        "wysoka": "high",
        "wysoki": "high",
        "high": "high",
        "średnie": "medium",
        "srednie": "medium",
        "średnia": "medium",
        "srednia": "medium",
        "średni": "medium",
        "sredni": "medium",
        "medium": "medium",
        "niskie": "low",
        "niska": "low",
        "niski": "low",
        "low": "low",
    }
    return mapping.get(v, "unknown")


# Explicit severity tokens. These are intentionally kept separate from CVSS.
# A report can contain a valid critical label even when the score is missing or
# rendered in a format that cannot be parsed. Such an occurrence must still be
# counted as critical in presentation metrics.
SEVERITY_TOKEN_RE = (
    r"krytyczne|krytyczna|krytyczny|"
    r"wysokie|wysoka|wysoki|"
    r"średnie|srednie|średnia|srednia|średni|sredni|"
    r"niskie|niska|niski|"
    r"critical|crit|high|medium|low|brak_danych"
)

CVSS_SCORE_TOKEN_RE = r"10(?:[.,]0+)?|[0-9](?:[.,][0-9]+)?"


def extract_explicit_severity(text: str) -> str:
    """
    Extract an explicitly stated textual severity from a *single CVE block*.

    Supported examples:
      (krytyczne, 9.8)
      (krytyczne, brak)
      Severity: CRITICAL
      Severity = critical
      Poziom: krytyczny
      Risk: HIGH
      [critical]
      CRITICAL (CVSS 9.8)

    The function deliberately does not classify prose such as
    "critical infrastructure" unless it appears in a severity-shaped form.
    """
    if not text:
        return "unknown"

    t = normalize_report_text(text)

    patterns = [
        # Native Artemis form: (krytyczne, 9.8) / (critical, CVSS: 9.8)
        rf"\(\s*({SEVERITY_TOKEN_RE})\s*,",
        # Explicit labels.
        rf"(?:severity|risk|poziom|ważność|waznosc|krytyczność|krytycznosc)\s*[:=\-]\s*({SEVERITY_TOKEN_RE})\b",
        # Nuclei-like / compact labels.
        r"\[(critical|high|medium|low)\]",
        # CRITICAL (9.8 CVSS) / CRITICAL (CVSS 9.8)
        rf"\b({SEVERITY_TOKEN_RE})\b\s*\(\s*(?:(?:CVSS[^0-9]{{0,20}})?{CVSS_SCORE_TOKEN_RE}|{CVSS_SCORE_TOKEN_RE}\s*CVSS)",
    ]

    for pat in patterns:
        m = re.search(pat, t, re.I)
        if m:
            return normalize_severity(m.group(1))

    return "unknown"


def extract_severity_cvss(text: str) -> Tuple[str, Optional[float]]:
    """
    Extract textual severity and numeric CVSS from one CVE finding block.

    CRITICAL COUNTING RULE USED BY THE SCRIPT:
      1. An explicit textual label "krytyczne" / "critical" is sufficient to
         classify that individual CVE occurrence as critical.
      2. Independently, any valid numeric CVSS >= 9.0 is critical.
      3. Numeric CVSS is still parsed whenever available and stored in Excel.
      4. A textual critical label is NOT discarded just because CVSS is absent.

    Supported CVSS forms include, among others:
      (krytyczne, 9.8)
      (krytyczne, 9,8)
      (krytyczne, CVSS 9.8)
      (critical, CVSS: 9.8)
      Severity: CRITICAL (9.8 CVSS v3.1)
      CVSS: 9.8
      CVSS 3.1: 9.8
      CVSS v3.1 Base Score: 9.8
      Base score: 9.8
      CVSS Score: 9.8
      CVSS: 9.8/10
    """
    if not text:
        return "unknown", None

    t = normalize_report_text(text)
    explicit_sev = extract_explicit_severity(t)
    score = None

    score_patterns = [
        # Native Artemis: (severity, score) or (severity, CVSS score)
        rf"\(\s*(?:{SEVERITY_TOKEN_RE})\s*,\s*(?:CVSS(?:\s*(?:v(?:ersion)?\s*)?[234](?:[.,]\d+|\.x)?)?\s*(?:base\s*score|score)?\s*[:=]?\s*)?({CVSS_SCORE_TOKEN_RE})\s*(?:/\s*10(?:[.,]0+)?)?\s*\)",
        # Label before score: CVSS 3.1: 9.8, CVSS v3.1 Base Score 9.8, CVSS Score: 9.8
        rf"\bCVSS(?:\s*(?:v(?:ersion)?\s*)?[234](?:[.,]\d+|\.x)?)?\s*(?:base\s*score|score)?\s*[:=\-]?\s*({CVSS_SCORE_TOKEN_RE})(?:\s*/\s*10(?:[.,]0+)?)?",
        # Base score: 9.8
        rf"\bbase\s*score\s*[:=\-]?\s*({CVSS_SCORE_TOKEN_RE})(?:\s*/\s*10(?:[.,]0+)?)?",
        # 9.8 CVSS v3.1
        rf"\b({CVSS_SCORE_TOKEN_RE})\s+CVSS(?:\s*(?:v(?:ersion)?\s*)?[234](?:[.,]\d+|\.x)?)?\b",
    ]

    for pat in score_patterns:
        m = re.search(pat, t, re.I)
        if not m:
            continue
        try:
            candidate = float(m.group(1).replace(",", "."))
        except Exception:
            continue
        if 0.0 <= candidate <= 10.0:
            score = candidate
            break

    # Keep explicit critical/high/etc. evidence. If no explicit label exists,
    # derive severity from CVSS for compatibility with existing sheets.
    sev = explicit_sev
    if sev == "unknown" and score is not None:
        if score >= 9.0:
            sev = "critical"
        elif score >= 7.0:
            sev = "high"
        elif score >= 4.0:
            sev = "medium"
        elif score > 0.0:
            sev = "low"
        else:
            sev = "unknown"

    # A numeric >=9 is always critical, even if the report text accidentally
    # carries a weaker label. This prevents undercounting malformed reports.
    if score is not None and score >= 9.0:
        sev = "critical"

    return sev, score


def normalize_cve_id(value: str) -> str:
    """
    Return canonical CVE-YYYY-NNNN form.

    Differences in case/whitespace/unicode separators must never split one CVE
    into multiple dashboard/ranking entries.
    """
    if value is None:
        return ""
    text = normalize_report_text(str(value))
    m = CVE_RE.search(text)
    return m.group(1).upper() if m else str(value).strip().upper()


def _valid_cvss_number(value) -> Optional[float]:
    """Return a valid CVSS base score in range 0..10 or None."""
    try:
        if value is None:
            return None
        s = str(value).strip()
        if not s or s.lower() in {"nan", "none", "brak", "brak_danych"}:
            return None
        score = float(s.replace(",", "."))
        if 0.0 <= score <= 10.0:
            return score
    except Exception:
        pass
    return None


def effective_severity_and_cvss(row) -> Tuple[str, Optional[float]]:
    """
    Resolve severity/CVSS for one finding occurrence.

    For current native HTML findings, Severity/CVSS are extracted from the
    PRIMARY finding header (the CVE that starts the <li>). Do not promote a
    finding to critical merely because a CVSS value or the word "critical"
    occurs later in descriptive prose.
    """
    if not hasattr(row, "get"):
        return "unknown", None

    stored_sev = normalize_severity(row.get("Severity", ""))
    score = _valid_cvss_number(row.get("CVSS", ""))

    evidence = str(row.get("Raw Finding", "") or "")[:700]
    parsed_sev, inferred_score = extract_severity_cvss(evidence)
    if score is None:
        score = _valid_cvss_number(inferred_score)
    sev = stored_sev if stored_sev != "unknown" else parsed_sev

    if score is not None:
        if score >= 9.0:
            return "critical", score
        if score >= 7.0:
            return "high", score
        if score >= 4.0:
            return "medium", score
        if score > 0.0:
            return "low", score
        return "unknown", score

    return sev, None


def severity_rank(value: str) -> int:
    """Stable severity order used by TOP5 ranking."""
    sev = normalize_severity(value)
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "unknown": 0,
    }.get(sev, 0)


def is_critical_record(row) -> bool:
    """
    Authoritative critical-occurrence predicate used by ALL dashboards/charts.

    A source occurrence is critical only when the PRIMARY finding has a valid
    numeric CVSS in the critical range 9.0..10.0.
    """
    _sev, score = effective_severity_and_cvss(row)
    return score is not None and 9.0 <= score <= 10.0


def canonical_presentation_class(group_value: str) -> str:
    """Map group labels such as 'PK', 'PK - wojskowe' or '[PI]' to PK/PI/PP."""
    g = str(group_value or "").strip().upper()
    for code in PRESENTATION_CLASSES:
        if re.search(rf"(?<![A-Z0-9]){code}(?![A-Z0-9])", g):
            return code
    return ""



def _nearest_asset_context_from_text(
    full_text: str,
    position: int,
    default_domain: str,
) -> Tuple[str, str, str]:
    """
    Resolve nearest preceding IP/domain/services context for a CVE position.
    Works for both historical and current report layouts.
    """
    before = full_text[:max(0, position)]

    ip = ""
    host = default_domain
    ip_matches = list(IP_HOST_RE.finditer(before))
    if ip_matches:
        last = ip_matches[-1]
        ip = last.group(1)
        host = normalize_domain_key(last.group(2)) or default_domain

    services = ""
    svc_matches = list(
        re.finditer(
            r"Widoczne serwisy\s*:\s*([^\n]+)",
            before,
            re.I,
        )
    )
    if svc_matches:
        services = svc_matches[-1].group(1).strip()

    return ip, host, services


def _li_text_without_nested_li(li) -> str:
    """
    Return normalized text belonging to one logical <li> finding only.

    Parent asset/container <li> elements often contain nested <li> vulnerability
    entries. Counting the parent together with its descendants duplicates CVEs.
    To avoid that, nested <li> elements are removed before extracting text.
    """
    try:
        local = BeautifulSoup(str(li), "html.parser")
        root = local.find("li")
        if root is None:
            return ""
        nested = root.find_all("li")
        for child in nested[1:]:
            child.decompose()
        return normalize_report_text(root.get_text("\n", strip=True))
    except Exception:
        return normalize_report_text(li.get_text("\n", strip=True))


def _primary_cve_from_html_finding(li, block: str) -> str:
    """
    Identify the CVE that LABELS this finding.

    Priority:
      1. first <strong>/<b> whose text is exactly a CVE identifier;
      2. first CVE token in the logical LI text.

    CVEs mentioned later inside the prose (for example "incomplete fix for
    CVE-2016-10009") are references and must NOT become independent findings.
    """
    for tag in li.find_all(["strong", "b"], recursive=True):
        txt = normalize_report_text(tag.get_text(" ", strip=True))
        m = CVE_RE.fullmatch(txt.strip())
        if m:
            return m.group(1).upper()

    m = CVE_RE.search(block)
    return m.group(1).upper() if m else ""


def _find_li_global_position(full_text: str, cve: str, block: str, cursor: int) -> Tuple[int, int]:
    """Find the next occurrence of this finding in full visible text."""
    # Prefer a short unique prefix from the LI so repeated CVEs on different
    # assets are mapped to the correct occurrence in document order.
    prefix = re.sub(r"\s+", " ", block).strip()[:220]
    pos = full_text.find(prefix, cursor) if prefix else -1
    if pos < 0:
        pos = full_text.find(cve, cursor)
    if pos < 0:
        pos = full_text.find(cve)
    if pos < 0:
        pos = 0
    return pos, max(cursor, pos + max(1, len(prefix)))




def extract_cve_records_raw_li(
    html_path: str,
    default_domain: str,
    group_map: Dict[str, str],
) -> List[Dict[str, object]]:
    """
    Authoritative HTML parser: ONE native vulnerability <li> == ONE occurrence.

    A finding is accepted only when the <li> itself (not a nested child <li>)
    owns a <strong>/<b> element whose text is exactly one CVE identifier.
    References to other CVEs later in the description remain description text.
    """
    if os.path.splitext(html_path)[1].lower() not in (".html", ".htm"):
        return []

    with open(html_path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    soup = BeautifulSoup(raw, "html.parser")
    full_text = normalize_report_text(soup.get_text("\n", strip=True))
    rows: List[Dict[str, object]] = []
    cursor = 0

    header_re = re.compile(
        r"^\s*(CVE-\d{4}-\d{4,})\s*"
        r"\(\s*(krytyczne|krytyczna|krytyczny|critical)\s*,\s*"
        r"(?:CVSS(?:\s*v?[234](?:[.,]\d|\.x)?)?\s*[:=]?\s*)?"
        r"(10(?:[.,]0)?|[0-9](?:[.,][0-9]+)?)\s*\)\s*: ?",
        re.I,
    )

    for li_index, li in enumerate(soup.find_all("li"), start=1):
        primary_tag = None
        primary_cve = ""
        for tag in li.find_all(["strong", "b"]):
            if tag.find_parent("li") is not li:
                continue
            txt = normalize_report_text(tag.get_text(" ", strip=True))
            m = CVE_RE.fullmatch(txt.strip())
            if m:
                primary_tag = tag
                primary_cve = m.group(1).upper()
                break
        if primary_tag is None:
            continue

        block = normalize_report_text(_li_text_without_nested_li(li))
        if not block:
            continue

        bm = CVE_RE.match(block.strip())
        if not bm or bm.group(1).upper() != primary_cve:
            continue

        hm = header_re.match(block.strip())
        if hm:
            severity = normalize_severity(hm.group(2))
            try:
                cvss_score = float(hm.group(3).replace(",", "."))
            except Exception:
                cvss_score = None
        else:
            heading = block[:500]
            severity, cvss_score = extract_severity_cvss(heading)

        global_pos, cursor = _find_li_global_position(full_text, primary_cve, block, cursor)
        ip, host, services = _nearest_asset_context_from_text(full_text, global_pos, default_domain)

        rec_match = re.search(r"(?:^|\n)\s*Rekomendacje?\s*:\s*(.*)$", block, re.I | re.S)
        recommendation = re.sub(r"\s+", " ", rec_match.group(1)).strip() if rec_match else ""

        pm = CVE_RE.match(block.strip())
        start_desc = pm.end() if pm else 0
        end_desc = rec_match.start() if rec_match else len(block)
        desc_region = block[start_desc:end_desc]
        desc_region = re.sub(r"^\s*[:\-–—•·‣]+\s*", "", desc_region)
        description = re.sub(r"\s+", " ", desc_region).strip()
        if len(description) > 5000:
            description = description[:5000] + "…"

        rows.append({
            "CVE": primary_cve,
            "IP": ip,
            "Domain": host or default_domain,
            "Group": group_for_domain(host or default_domain, group_map),
            "Services": services,
            "Severity": severity,
            "CVSS": cvss_score if cvss_score is not None else "",
            "Description": description,
            "Recommendation": recommendation,
            "Source File": os.path.basename(html_path),
            "Source Path": os.path.abspath(html_path),
            "Occurrence ID": f"{sha1_text(os.path.abspath(html_path))[:16]}::li::{li_index:06d}",
            "Raw Finding": re.sub(r"\s+", " ", block).strip(),
        })

    return rows


def extract_cve_records_structured_html(
    html_path: str,
    default_domain: str,
    group_map: Dict[str, str],
) -> List[Dict[str, str]]:
    """
    Parse HTML reports at the finding-container level.

    IMPORTANT INVARIANT:
        one logical vulnerability <li> == one finding occurrence.

    Example:
        <li><strong>CVE-2023-38408</strong> (krytyczne, 9.8): ...
            ... incomplete fix for <strong>CVE-2016-10009</strong> ...</li>

    This produces exactly ONE finding: CVE-2023-38408 / critical / 9.8.
    CVE-2016-10009 is only a reference inside the description.
    """
    if os.path.splitext(html_path)[1].lower() == ".pdf":
        return []

    with open(html_path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    soup = BeautifulSoup(raw, "html.parser")
    full_text = normalize_report_text(soup.get_text("\n", strip=True))
    rows: List[Dict[str, str]] = []
    cursor = 0

    for li_index, li in enumerate(soup.find_all("li"), start=1):
        block = _li_text_without_nested_li(li)
        if not block or not CVE_RE.search(block):
            continue

        cve = _primary_cve_from_html_finding(li, block)
        if not cve:
            continue

        # Require this LI to look like a vulnerability entry rather than a
        # generic prose bullet that merely references a CVE. Strong/bold CVE
        # labels are accepted immediately. Otherwise require severity/CVSS near
        # the beginning of the block.
        has_bold_primary = False
        for tag in li.find_all(["strong", "b"], recursive=True):
            txt = normalize_report_text(tag.get_text(" ", strip=True)).strip()
            if txt.upper() == cve:
                has_bold_primary = True
                break

        head = block[:500]
        sev_head, score_head = extract_severity_cvss(head)
        has_severity_evidence = (
            sev_head != "unknown"
            or score_head is not None
            or bool(re.search(r"\b(?:krytyczn\w*|critical|wysok\w*|high|średni\w*|sredni\w*|medium|niski\w*|niskie|low)\b", head, re.I))
            or bool(re.search(r"\bCVSS\b", head, re.I))
        )
        if not has_bold_primary and not has_severity_evidence:
            continue

        global_pos, cursor = _find_li_global_position(full_text, cve, block, cursor)
        ip, host, services = _nearest_asset_context_from_text(
            full_text,
            global_pos,
            default_domain,
        )

        severity, cvss_score = extract_severity_cvss(block)

        # Explicit Polish/English critical marker is authoritative evidence even
        # if a malformed report prevents numeric CVSS extraction.
        if severity == "unknown" and re.search(
            r"(?:\(|\b)(?:krytyczne|krytyczna|krytyczny|critical|crit)(?:\b|\s*,)",
            block[:500],
            re.I,
        ):
            severity = "critical"
        if cvss_score is not None and cvss_score >= 9.0:
            severity = "critical"

        rec_match = re.search(
            r"(?:^|\n)\s*Rekomendacje?\s*:\s*(.*)$",
            block,
            re.I | re.S,
        )
        recommendation = ""
        if rec_match:
            recommendation = re.sub(r"\s+", " ", rec_match.group(1)).strip()

        # Description begins after the PRIMARY CVE token and retains references
        # to other CVEs in the prose.
        pm = CVE_RE.search(block)
        desc_region = block[pm.end():] if pm else block
        if rec_match:
            # rec_match offsets refer to the full block.
            desc_region = block[(pm.end() if pm else 0):rec_match.start()]
        desc_region = re.sub(r"^\s*[:\-–—•·‣]+\s*", "", desc_region)
        description = re.sub(r"\s+", " ", desc_region).strip()
        if len(description) > 5000:
            description = description[:5000] + "…"

        rows.append({
            "CVE": cve,
            "IP": ip,
            "Domain": host or default_domain,
            "Group": group_for_domain(host or default_domain, group_map),
            "Services": services,
            "Severity": severity,
            "CVSS": cvss_score if cvss_score is not None else "",
            "Description": description,
            "Recommendation": recommendation,
            "Source File": os.path.basename(html_path),
            "Source Path": os.path.abspath(html_path),
            "Occurrence ID": f"{sha1_text(os.path.abspath(html_path))[:16]}::li::{li_index:06d}",
            "Raw Finding": re.sub(r"\s+", " ", block).strip(),
        })

    return rows

def _merge_cve_record_sets(
    record_sets: Iterable[List[Dict[str, object]]],
) -> List[Dict[str, object]]:
    """
    Merge CVEs produced by multiple parser strategies.

    Identity is CVE + normalized Domain + IP. Richer metadata wins field by
    field. Numeric values such as CVSS are handled safely.
    """
    merged: Dict[Tuple[str, str, str], Dict[str, object]] = {}

    def richness(value) -> int:
        if value is None:
            return 0
        try:
            if pd.isna(value):
                return 0
        except Exception:
            pass
        return len(str(value).strip())

    for records in record_sets:
        for r in records or []:
            cve = str(r.get("CVE", "") or "").upper().strip()
            domain = normalize_domain_key(r.get("Domain", ""))
            ip = str(r.get("IP", "") or "").strip()
            if not cve or not CVE_RE.fullmatch(cve):
                continue

            key = (cve, domain, ip)
            if key not in merged:
                merged[key] = dict(r)
                continue

            dst = merged[key]
            for field in [
                "Services",
                "Severity",
                "CVSS",
                "Description",
                "Recommendation",
                "Raw Finding",
                "Group",
                "Source File",
            ]:
                if richness(r.get(field, "")) > richness(dst.get(field, "")):
                    dst[field] = r.get(field, "")

    return list(merged.values())



def extract_cve_records_pdf(
    pdf_path: str,
    default_domain: str,
    group_map: Dict[str, str],
) -> List[Dict[str, object]]:
    """
    Authoritative parser for text-based PDF reports.

    Unlike the generic text parser, this function NEVER treats every CVE token
    in prose as a new finding. A new PDF finding starts only at a primary finding
    header with the report's native shape, for example:

        CVE-2017-11147 (krytyczne, 9.1): ...
        CVE-2024-12345 (wysokie, CVSS: 8.8): ...
        CVE-2024-12345\n(krytyczne, 9.8): ...

    CVE references inside descriptions therefore remain description text.
    Every matched primary header contributes exactly ONE source occurrence.
    """
    if os.path.splitext(pdf_path)[1].lower() != ".pdf":
        return []

    text = read_pdf_text(pdf_path)
    if not text.strip():
        raise RuntimeError(
            f"PDF contains no extractable text (OCR may be required): {pdf_path}"
        )

    severity_token = (
        r"krytyczne|krytyczna|krytyczny|critical|"
        r"wysokie|wysoka|wysoki|high|"
        r"średnie|srednie|średnia|srednia|średni|sredni|medium|"
        r"niskie|niska|niski|low|brak_danych"
    )
    score_token = r"10(?:[.,]0)?|[0-9](?:[.,][0-9]+)?"

    # Start of a logical vulnerability. The line-start anchor is essential: a
    # CVE mentioned later in prose is not allowed to create another finding.
    header_re = re.compile(
        rf"(?im)^[ \t]*(?:[•·‣◦▪●○►▸➤➜*-]+[ \t]*)?"
        rf"(?P<cve>CVE-\d{{4}}-\d{{4,}})"
        rf"[ \t]*(?:\n[ \t]*)?"
        rf"\(\s*(?P<severity>{severity_token})\s*,\s*"
        rf"(?:CVSS(?:\s*v?[234](?:[.,]\d|\.x)?)?(?:\s+Base\s+Score)?\s*[:=]?\s*)?"
        rf"(?P<score>{score_token}|brak)\s*\)\s*: ?",
        re.I | re.M,
    )

    matches = list(header_re.finditer(text))
    rows: List[Dict[str, object]] = []
    path_hash = sha1_text(os.path.abspath(pdf_path))[:16]

    for i, m in enumerate(matches):
        cve = normalize_cve_id(m.group("cve"))
        sev = normalize_severity(m.group("severity"))
        raw_score = m.group("score")
        cvss_score = None
        if raw_score and raw_score.lower() != "brak":
            try:
                cvss_score = float(raw_score.replace(",", "."))
            except Exception:
                cvss_score = None

        # Numeric CVSS is authoritative for the stored severity.
        if cvss_score is not None:
            if 9.0 <= cvss_score <= 10.0:
                sev = "critical"
            elif cvss_score >= 7.0:
                sev = "high"
            elif cvss_score >= 4.0:
                sev = "medium"
            elif cvss_score > 0.0:
                sev = "low"
            else:
                sev = "unknown"

        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end].strip()

        # Prevent the last finding from swallowing standard report boilerplate.
        boundary = re.search(
            r"\n(?=(?:\d+\.\s*)?(?:IP:|Widoczne serwisy:|CVEs?:|"
            r"Następujące|Poniższe|Pod następującymi|Pod poniższymi|"
            r"Jeżeli któreś|Prosimy pamiętać|Zalecamy przeprowadzić))",
            block[m.end()-m.start():],
            re.I,
        )
        if boundary:
            end_local = (m.end() - m.start()) + boundary.start()
            block = block[:end_local].strip()

        ip, host, services = _nearest_asset_context_from_text(
            text, start, default_domain
        )

        rec_match = re.search(
            r"(?:^|\n)\s*Rekomendacje?\s*:\s*(.*)$",
            block,
            re.I | re.S,
        )
        recommendation = (
            re.sub(r"\s+", " ", rec_match.group(1)).strip()
            if rec_match else ""
        )

        # Description begins immediately after the complete primary header.
        header_len = m.end() - m.start()
        desc_end = rec_match.start() if rec_match else len(block)
        desc_region = block[header_len:desc_end]
        description = re.sub(r"\s+", " ", desc_region).strip(" :-\t")
        if len(description) > 5000:
            description = description[:5000] + "…"

        rows.append({
            "CVE": cve,
            "IP": ip,
            "Domain": host or default_domain,
            "Group": group_for_domain(host or default_domain, group_map),
            "Services": services,
            "Severity": sev,
            "CVSS": cvss_score if cvss_score is not None else "",
            "Description": description,
            "Recommendation": recommendation,
            "Source File": os.path.basename(pdf_path),
            "Source Path": os.path.abspath(pdf_path),
            "Occurrence ID": f"{path_hash}::pdfheader::{i + 1:06d}",
            "Raw Finding": re.sub(r"\s+", " ", block).strip(),
        })

    return rows


def extract_cve_records_text(
    html_path: str,
    default_domain: str,
    group_map: Dict[str, str],
) -> List[Dict[str, str]]:
    """
    Extract every CVE occurrence from a report.

    CVEs are detected from the complete normalized visible HTML text, not only
    from a particular <ul>/<li> structure. Therefore all of the following are
    equivalent:
        CVE-2021-34798 ...
        • CVE-2021-34798 ...
        · CVE-2021-34798 ...
        <li>CVE-2021-34798 ...</li>

    Association with IP/host/services is performed using the nearest preceding
    asset header in the report.
    """
    _, text, _ = read_html(html_path)
    matches = list(CVE_RE.finditer(text))
    rows: List[Dict[str, str]] = []

    for i, m in enumerate(matches):
        cve = m.group(1).upper()
        start = m.start()

        # Every CVE ends no later than the next CVE. This makes parsing
        # independent from list bullets / <li> boundaries.
        natural_end = (
            matches[i + 1].start()
            if i + 1 < len(matches)
            else min(len(text), m.end() + 12000)
        )

        # The last CVE in an asset block must stop before a new independent
        # report/configuration section.
        tail = text[m.end():natural_end]
        boundary = re.search(
            r"\n(?="
            r"(?:\d+\.\s*)?"
            r"(?:"
            r"IP:|Widoczne serwisy:|CVEs?:|"
            r"Następujące|Poniższe|Pod następującymi|Pod poniższymi|"
            r"Wykryto|Nie znaleziono|Polityka|Rekord|Problem|Ostrzeżenie|"
            r"Certyfikat|Certyfikaty|Brak |Domena |"
            r"Jeżeli któreś|Prosimy pamiętać|Zalecamy przeprowadzić"
            r")"
            r")",
            tail,
            re.I,
        )
        end = m.end() + boundary.start() if boundary else natural_end

        segment = text[m.end():end].strip()
        before = text[:start]

        # Nearest preceding IP: x.x.x.x (host) determines the affected asset.
        ip = ""
        host = default_domain
        ip_matches = list(IP_HOST_RE.finditer(before))
        if ip_matches:
            ip = ip_matches[-1].group(1)
            host = (
                normalize_domain_key(ip_matches[-1].group(2))
                or default_domain
            )

        # Nearest visible-services declaration preceding this CVE.
        services = ""
        svc_matches = list(
            re.finditer(
                r"Widoczne serwisy:\s*([^\n]+)",
                before,
                re.I,
            )
        )
        if svc_matches:
            services = svc_matches[-1].group(1).strip()

        # Recommendation belongs only to this CVE segment. Since segment already
        # ends at the next CVE, bullets/list markup cannot make it absorb the
        # following vulnerability.
        rec_match = re.search(
            r"(?:^|\n)\s*Rekomendacje?\s*:\s*(.*)$",
            segment,
            re.I | re.S,
        )
        recommendation = ""
        if rec_match:
            recommendation = re.sub(
                r"\s+",
                " ",
                rec_match.group(1),
            ).strip()

        desc_part = (
            segment[:rec_match.start()]
            if rec_match
            else segment
        )

        # Remove a leading punctuation/list residue but retain severity data.
        desc_part = re.sub(
            r"^\s*(?:[:\-–—•·‣]+\s*)",
            "",
            desc_part,
        )
        desc_part = re.split(
            r"\n(?:"
            r"Zalecamy przeprowadzić|"
            r"Jeżeli któreś|"
            r"Prosimy pamiętać"
            r")",
            desc_part,
            maxsplit=1,
            flags=re.I,
        )[0]

        description = re.sub(r"\s+", " ", desc_part).strip()
        if len(description) > 5000:
            description = description[:5000] + "…"

        # Parse severity/CVSS from the full local CVE block. This supports both:
        #   CVE-... (wysokie, 7.5):
        # and:
        #   Severity:
        #   HIGH (7.5 CVSS v3.x)
        local_block = text[start:min(len(text), end)]
        severity, cvss_score = extract_severity_cvss(local_block)

        raw_fragment = re.sub(
            r"\s+",
            " ",
            text[max(0, start - 250):min(len(text), end)],
        ).strip()

        rows.append({
            "CVE": cve,
            "IP": ip,
            "Domain": host or default_domain,
            "Group": group_for_domain(
                host or default_domain,
                group_map,
            ),
            "Services": services,
            "Severity": severity,
            "CVSS": cvss_score if cvss_score is not None else "",
            "Description": description,
            "Recommendation": recommendation,
            "Source File": os.path.basename(html_path),
            "Source Path": os.path.abspath(html_path),
            "Occurrence ID": f"{sha1_text(os.path.abspath(html_path))[:16]}::text::{i + 1:06d}",
            "Raw Finding": raw_fragment,
        })

    # IMPORTANT:
    # Do NOT deduplicate CVE+Domain+IP here.
    # Every CVE occurrence in the source report is a real finding occurrence
    # and must remain available for critical-count metrics / graphs.
    return rows


def extract_cve_records(
    html_path: str,
    default_domain: str,
    group_map: Dict[str, str],
) -> List[Dict[str, object]]:
    """
    Extract CVE findings without double counting.

    HTML native <li> findings are authoritative and are NEVER merged with or
    replaced by another parser merely because another parser returned more rows.
    """
    ext = os.path.splitext(html_path)[1].lower()

    if ext in (".html", ".htm"):
        try:
            native_rows = extract_cve_records_raw_li(html_path, default_domain, group_map)
        except Exception:
            native_rows = []
        if native_rows:
            return native_rows

        try:
            structured_rows = extract_cve_records_structured_html(html_path, default_domain, group_map)
        except Exception:
            structured_rows = []
        if structured_rows:
            seen_occ = set()
            out = []
            for r in structured_rows:
                occ = str(r.get("Occurrence ID", "") or "")
                if occ in seen_occ:
                    continue
                seen_occ.add(occ)
                out.append(r)
            return out

        # Unusual HTML without native LI finding containers.
        return extract_cve_records_text(html_path, default_domain, group_map)

    if ext == ".pdf":
        # PDF uses its own strict primary-header parser. Do not run the generic
        # every-CVE text parser because CVE references in descriptions would
        # otherwise become false additional findings.
        return extract_cve_records_pdf(html_path, default_domain, group_map)

    return []


def detect_config_category_presence(text: str) -> List[str]:
    """Return every known canonical configuration category present in report text."""
    blob = normalize_report_text(text or "")
    found = []
    for name, pat in CONFIG_CHECKS_COMPILED:
        if pat.search(blob):
            found.append(name)
    return found


def config_presence_details(text: str, description: str) -> str:
    """Return local evidence around all matches for one known config category."""
    blob = normalize_report_text(text or "")
    pat = None
    for name, compiled in CONFIG_CHECKS_COMPILED:
        if name == description:
            pat = compiled
            break
    if pat is None:
        return description
    matches = list(pat.finditer(blob))
    if not matches:
        return description
    chunks = []
    for m in matches:
        a = max(0, m.start() - 700)
        b = min(len(blob), m.end() + 2200)
        chunks.append(blob[a:b])
    return "\n".join(chunks).strip()


def _sanitize_config_details(text: str) -> str:
    """Remove CVE/product-vulnerability payload lines while preserving config evidence."""
    if not text:
        return ""
    out = []
    for raw in normalize_report_text(text).splitlines():
        line = raw.strip()
        if not line:
            continue
        # Never copy explicit CVE rows into Config_*.
        if CVE_RE.search(line):
            continue
        # Remove native CVE severity/description rows even if an upstream HTML
        # conversion separated the CVE token from the rest of the sentence.
        if CVSS_PREFIX_RE.search(line):
            continue
        # Recommendation prose attached to CVEs is not a configuration finding.
        if re.match(r"^\s*Rekomendacje?\s*:", line, re.I) and not CONFIG_SIGNAL_RE.search(line):
            continue
        out.append(line)
    return "\n".join(out).strip()


def extract_config_records(html_path: str, default_domain: str, group_map: Dict[str, str]) -> List[Dict[str, str]]:
    """
    Extract strictly configuration/exposure findings.

    Rules:
      1. CVE identifiers never enter Config_*.
      2. CVSS-annotated/product-vulnerability prose never enters Config_* even
         when the CVE token itself was removed upstream.
      3. If an HTML block originally contains CVEs, generic fallback is disabled
         for that block. Only explicit known configuration patterns can be
         extracted from its non-CVE remainder.
      4. Pure non-CVE blocks may use generic fallback, but only when they contain
         explicit configuration/exposure/control signals.
    """
    soup, text, lines = read_html(html_path)

    # Parse both historical nested lists and current top-level report blocks.
    if soup is not None:
        blocks = all_li_blocks(soup)
        if not blocks:
            blocks = top_level_li_blocks(soup)
    else:
        blocks = []

    if not blocks:
        blocks = fallback_finding_blocks(lines)

    rows: List[Dict[str, str]] = []
    seen = set()

    def add_record(desc: str, details: str):
        desc = (desc or "").strip()
        details = strip_excluded_config_lines((details or "").strip())
        if not desc or not details:
            return

        desc = canonical_config_description(desc, details)
        if not desc or is_hard_excluded_config_text(desc):
            return
        # Never create generic noise categories such as Ostrzezenie/Warning.
        if is_meaningless_config_label(desc):
            return
        if re.fullmatch(r"(?:Ostrzeżenie|Ostrzezenie|Warning)\s*: ?", desc, re.I):
            return
        if looks_like_product_vulnerability_text(desc) or looks_like_product_vulnerability_text(details):
            return
        if CVE_RE.search(desc) or CVE_RE.search(details):
            return
        if not is_explicit_configuration_finding(details):
            return

        urls, domains, ips = extract_urls_domains_ips(details, default_domain)
        fingerprint = sha1_text(re.sub(r"\s+", " ", details).lower())
        key = (desc.lower(), default_domain.lower(), fingerprint)
        if key in seen:
            return
        seen.add(key)

        record = {
            "Description": desc,
            "Domain": default_domain,
            "Group": group_for_domain(default_domain, group_map),
            "Affected Domains": domains,
            "Affected IPs": ips,
            "URLs/Resources": urls,
            "Details": details,
            "Source File": os.path.basename(html_path),
            "Finding Fingerprint": fingerprint,
        }
        if config_record_is_strictly_non_cve(record):
            rows.append(record)

    for original_block in blocks:
        if is_boilerplate(original_block):
            continue

        original_had_cve = bool(CVE_RE.search(original_block))
        block = strip_cve_content_from_block(original_block)
        if not block or is_boilerplate(block):
            continue

        # Remove leftover CVSS/product vulnerability paragraphs that no longer
        # contain the literal CVE ID.
        clean_lines = []
        for ln in block.splitlines():
            if looks_like_product_vulnerability_text(ln):
                continue
            clean_lines.append(ln)
        block = re.sub(r"\n{3,}", "\n\n", "\n".join(clean_lines)).strip()
        if not block:
            continue

        # Extract every known configuration category independently. This is
        # important for mixed Artemis asset blocks containing several findings.
        matched_known = False
        for name, pat in CONFIG_CHECKS_COMPILED:
            mm = pat.search(block)
            if not mm:
                continue
            matched_known = True

            # Jeden logiczny rekord na kategorię w danym bloku. Wiele URL-i lub
            # powtarzające się pola (np. kilka "AD domain name:") są szczegółami
            # jednego findingu, a nie osobnymi błędami konfiguracyjnymi.
            a = max(0, mm.start() - 500)
            b = min(len(block), mm.end() + 2400)
            ctx_lines = []
            for ln in block[a:b].splitlines():
                if CVE_RE.search(ln) or looks_like_product_vulnerability_text(ln):
                    continue
                ctx_lines.append(ln)
            details = re.sub(r"\n{3,}", "\n\n", "\n".join(ctx_lines)).strip()
            if details:
                add_record(name, details)

        # Generic fallback is intentionally forbidden for a block that had CVE,
        # because residual description text is too easy to misclassify.
        if original_had_cve:
            continue

        if not matched_known and is_explicit_configuration_finding(block):
            desc = classify_config_description(block, default_domain)
            if desc:
                add_record(desc, block)

    # Fallback across the complete report, but only for known configuration
    # signatures. No generic full-report fallback is used.
    non_cve_text = strip_cve_content_from_block(text)
    safe_lines = [
        ln for ln in non_cve_text.splitlines()
        if not looks_like_product_vulnerability_text(ln)
    ]
    non_cve_text = "\n".join(safe_lines)

    existing = {(r["Description"], r["Domain"]) for r in rows}
    for name, pat in CONFIG_CHECKS_COMPILED:
        if (name, default_domain) in existing:
            continue
        mm = pat.search(non_cve_text)
        if not mm:
            continue

        # Known CONFIG_CHECKS are authoritative. Build evidence from the
        # matched line(s), not from a large surrounding window that may contain
        # unrelated CVE prose and cause the valid configuration finding to be
        # rejected. This is especially important for standalone HTML such as:
        #   <p>Brak ustawienia ciasteczka SameSite</p>
        line_start = non_cve_text.rfind("\n", 0, mm.start()) + 1
        line_end = non_cve_text.find("\n", mm.end())
        if line_end < 0:
            line_end = len(non_cve_text)
        matched_line = non_cve_text[line_start:line_end].strip()

        details = _sanitize_config_details(matched_line)
        if not details:
            details = _sanitize_config_details(mm.group(0))
        if not details:
            details = name

        before = len(rows)
        add_record(name, details)
        if len(rows) > before:
            existing.add((name, default_domain))

    # Hard final dedupe/validation.
    final_rows: List[Dict[str, str]] = []
    final_seen = set()
    for r in rows:
        r = dict(r)
        r["Details"] = strip_excluded_config_lines(str(r.get("Details", "") or ""))
        r["Description"] = canonical_config_description(
            str(r.get("Description", "") or ""),
            r["Details"],
        )
        if not r["Description"] or is_hard_excluded_config_text(r["Description"]):
            continue
        blob = " ".join(str(r.get(k, "") or "") for k in ("Description", "Details", "URLs/Resources"))
        if CVE_RE.search(blob) or looks_like_product_vulnerability_text(blob):
            continue
        if not is_explicit_configuration_finding(blob):
            continue
        key = (
            str(r.get("Description", "")).strip().lower(),
            normalize_domain_key(r.get("Domain", "")),
            str(r.get("Finding Fingerprint", "")).strip(),
        )
        if key in final_seen:
            continue
        final_seen.add(key)
        final_rows.append(r)

    return final_rows




def extract_all_finding_blocks(html_path: str, default_domain: str, group_map: Dict[str, str]) -> List[Dict[str, str]]:
    soup, text, lines = read_html(html_path)
    blocks = top_level_li_blocks(soup) or fallback_finding_blocks(lines)
    rows = []
    for block in blocks:
        if is_boilerplate(block):
            continue
        urls, domains, ips = extract_urls_domains_ips(block, default_domain)
        cves = stable_join(x.upper() for x in CVE_RE.findall(block))
        category = "CVE" if cves else "Configuration/Other"
        rows.append({
            "Type": category,
            "Domain": default_domain,
            "Group": group_for_domain(default_domain, group_map),
            "CVEs": cves,
            "Affected Domains": domains,
            "Affected IPs": ips,
            "URLs/Resources": urls,
            "Details": block,
            "Source File": os.path.basename(html_path),
        })
    return rows


# ---------------------------------------------------------------------------
# Folder processing / dataframe construction
# ---------------------------------------------------------------------------

def aggregate_cves(detail_df: pd.DataFrame) -> pd.DataFrame:
    if detail_df.empty:
        return pd.DataFrame(columns=["CVE", "Statistics", "Domains", "Group", "IP", "Services", "Severity", "CVSS"])
    rows = []
    for cve, g in detail_df.groupby("CVE", dropna=False):
        rows.append({
            "CVE": cve,
            "Statistics": int(len(g)),
            "Domains": stable_join(g["Domain"].astype(str)),
            "Group": stable_join(g["Group"].astype(str)),
            "IP": stable_join(g["IP"].astype(str)),
            "Services": stable_join(g["Services"].astype(str)) if "Services" in g.columns else "",
            "Severity": stable_join(g["Severity"].astype(str)) if "Severity" in g.columns else "",
            "CVSS": pd.to_numeric(g["CVSS"], errors="coerce").max() if "CVSS" in g.columns else "",
        })
    return pd.DataFrame(rows).sort_values(["Statistics", "CVE"], ascending=[False, True], kind="stable").reset_index(drop=True)




def _split_csv_values(value: object) -> List[str]:
    """Split comma/semicolon/newline-separated evidence values."""
    if value is None:
        return []
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none"}:
        return []
    return [x.strip() for x in re.split(r"[,;\n]+", text) if x.strip()]


def _config_main_domain(row) -> str:
    """
    Return the reporting/main domain for a configuration finding.

    IMPORTANT COUNTING RULE:
      - A configuration category is counted ONCE per reporting domain/entity.
      - Affected Domains / URLs / endpoints are evidence only and NEVER multiply
        the configuration count.

    Example:
      report Domain = example.pl
      Affected Domains = a.example.pl, b.example.pl, c.example.pl
      SameSite => Count +1, Domains contains example.pl once.
    """
    if not hasattr(row, "get"):
        return ""
    d = normalize_domain_key(str(row.get("Domain", "") or ""))
    if d.startswith("www."):
        d = d[4:]
    return d


def dedupe_config_by_domain_category(config_detail_df: pd.DataFrame) -> pd.DataFrame:
    """
    Reduce configuration findings to exactly one logical occurrence per:
        canonical configuration category + reporting/main domain.

    Subdomains, URLs, endpoints and repeated mentions remain available as
    evidence in Config_Detailed, but they do NOT increase Count.
    """
    if config_detail_df is None or config_detail_df.empty:
        return config_detail_df.copy() if config_detail_df is not None else pd.DataFrame()

    df = config_detail_df.copy()
    df["Description"] = df.apply(
        lambda r: canonical_config_description(
            r.get("Description", ""),
            r.get("Details", ""),
        ),
        axis=1,
    )
    df["__main_domain"] = df.apply(_config_main_domain, axis=1)

    # Final hard guard: never expose generic warning labels as config findings.
    bad_warning = df["Description"].fillna("").astype(str).str.fullmatch(
        r"(?i)\s*(?:ostrzeżenie|ostrzezenie|warning)\s*[:.!-]?\s*",
        na=False,
    )
    df = df.loc[~bad_warning].copy()

    df = df[
        (df["Description"].fillna("").astype(str).str.strip() != "")
        & (df["__main_domain"].fillna("").astype(str).str.strip() != "")
    ].copy()

    representatives = []
    for (_desc, _domain), g in df.groupby(
        ["Description", "__main_domain"], dropna=False, sort=False
    ):
        g = g.copy()

        def richness(row):
            return sum(
                len(str(row.get(col, "") or "").strip())
                for col in (
                    "Details", "URLs/Resources", "Affected Domains",
                    "Affected IPs", "Source File"
                )
            )

        best_idx = max(g.index, key=lambda idx: richness(g.loc[idx]))
        row = g.loc[best_idx].copy()

        # Preserve ALL evidence from all repeated instances without multiplying
        # the logical finding count.
        if "Affected Domains" in g.columns:
            vals = []
            for v in g["Affected Domains"].astype(str):
                vals.extend(_split_csv_values(v))
            row["Affected Domains"] = stable_join(vals)
        if "Affected IPs" in g.columns:
            vals = []
            for v in g["Affected IPs"].astype(str):
                vals.extend(_split_csv_values(v))
            row["Affected IPs"] = stable_join(vals)
        if "URLs/Resources" in g.columns:
            vals = []
            for v in g["URLs/Resources"].astype(str):
                vals.extend(_split_csv_values(v))
            row["URLs/Resources"] = stable_join(vals)
        if "Source File" in g.columns:
            row["Source File"] = stable_join(g["Source File"].astype(str))

        row["Domain"] = _domain
        row["Finding Fingerprint"] = sha1_text(f"{_desc}|{_domain}".lower())
        representatives.append(row)

    out = pd.DataFrame(representatives)
    if "__main_domain" in out.columns:
        out = out.drop(columns=["__main_domain"])
    return out.reset_index(drop=True)


def aggregate_config(config_detail_df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate configuration findings by category.

    Count = number of UNIQUE reporting/main domains affected by the category.
    Domains = those main domains only.

    Three subdomains affected by SameSite inside one entity/report therefore
    produce Count=1 and one main domain in Domains.
    """
    if config_detail_df is None or config_detail_df.empty:
        return pd.DataFrame(columns=["Description", "Count", "Domains", "Group"])

    df = dedupe_config_by_domain_category(config_detail_df)
    if df.empty:
        return pd.DataFrame(columns=["Description", "Count", "Domains", "Group"])

    rows = []
    for desc, g in df.groupby("Description", dropna=False):
        domains_list = sorted({
            _config_main_domain(r)
            for _, r in g.iterrows()
            if _config_main_domain(r)
        })
        rows.append({
            "Description": desc,
            "Count": len(domains_list),
            "Domains": ", ".join(domains_list),
            "Group": stable_join(g["Group"].astype(str)),
        })

    return (
        pd.DataFrame(rows)
        .sort_values(["Count", "Description"], ascending=[False, True], kind="stable")
        .reset_index(drop=True)
    )


def discover_html_source_folders(root_folder: str) -> List[str]:
    """
    Find every folder that directly contains HTML/PDF reports.
    Supports HTMLs in root and in nested folders.
    """
    root = os.path.abspath(root_folder)
    folders: Set[str] = set()
    excluded = {"excel", "__pycache__"}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in excluded and not d.startswith(".")
        ]
        if any(name.lower().endswith((".html", ".htm", ".pdf")) for name in filenames):
            folders.add(os.path.abspath(dirpath))

    def sort_key(path: str):
        base = os.path.basename(os.path.normpath(path)).lower()
        try:
            known_idx = KNOWN_SUBFOLDERS.index(base)
        except ValueError:
            known_idx = len(KNOWN_SUBFOLDERS)
        return (known_idx, os.path.relpath(path, root).lower())

    return sorted(folders, key=sort_key)


def unique_folder_label(
    folder: str,
    root_folder: str,
    used: Set[str],
) -> str:
    """Create a stable unique label for workbook sheet prefixes."""
    base = os.path.basename(os.path.normpath(folder)) or "HTML_REPORTS"
    candidate = base

    if candidate.upper() not in used:
        used.add(candidate.upper())
        return candidate

    rel = os.path.relpath(folder, root_folder)
    candidate = re.sub(r"[^A-Za-z0-9._-]+", "_", rel).strip("_") or base
    original = candidate
    n = 2
    while candidate.upper() in used:
        candidate = f"{original}_{n}"
        n += 1

    used.add(candidate.upper())
    return candidate



def audit_config_detection_for_file(
    html_path: str,
    default_domain: str,
    extracted_rows: List[Dict[str, str]],
    log_fp=None,
) -> None:
    """
    Audit known-category presence against extracted logical rows.
    Logs any category that exists in full report text but was not represented.
    """
    try:
        _, text, _ = read_html(html_path)
    except Exception as exc:
        log_line(f"[!] CONFIG audit read failed for {html_path}: {exc}", log_fp)
        return

    expected = set(detect_config_category_presence(text))
    actual = {
        canonical_config_description(
            r.get("Description", ""),
            r.get("Details", ""),
        )
        for r in extracted_rows
        if r
    }
    actual.discard("")

    missing = sorted(expected - actual)
    if missing:
        log_line(
            f"[!] CONFIG AUDIT missing categories for {os.path.basename(html_path)} "
            f"({default_domain}): {', '.join(missing)}",
            log_fp,
        )



def raw_critical_occurrences_in_report(path: str) -> Tuple[int, int]:
    """
    Count logical source CVE findings using the SAME authoritative parser that
    is used to populate All_data_detailed.

    Why this matters:
      - HTML may use native <li><strong>CVE...</strong> findings, but older or
        unusual reports can require the structured/text fallback parser.
      - PDF uses the strict primary-header parser.
      - The previous independent HTML-only LI audit could report raw=404 while
        the authoritative parser correctly returned parsed=405, causing a false
        fatal mismatch.

    This function therefore audits parser output one-to-one. A separate native
    critical-header counter below is used as an additional diagnostic and does
    not redefine the number of logical findings.
    """
    default_domain = normalize_domain_key(
        os.path.splitext(os.path.basename(path))[0]
    )
    try:
        rows = extract_cve_records(path, default_domain, {})
    except Exception:
        return 0, 0

    logical = len(rows)
    critical = sum(1 for r in rows if is_critical_record(r))
    return logical, critical


def native_critical_headers_in_report(path: str) -> int:
    """
    Diagnostic count of explicit PRIMARY critical headers with numeric
    CVSS 9.0..10.0.

    This is intentionally independent from dashboard aggregation and is used
    only for logging. It approximates the user's grep-style validation while
    avoiding CVE/CVSS references that occur later in descriptions.
    """
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext in ('.html', '.htm'):
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                raw = f.read()
            soup = BeautifulSoup(raw, 'html.parser')
            count = 0
            for li in soup.find_all('li'):
                # Only a CVE label owned directly by this LI is a primary finding.
                primary = None
                for tag in li.find_all(['strong', 'b']):
                    if tag.find_parent('li') is not li:
                        continue
                    txt = normalize_report_text(tag.get_text(' ', strip=True)).strip()
                    m = CVE_RE.fullmatch(txt)
                    if m:
                        primary = m.group(1).upper()
                        break
                if not primary:
                    continue

                block = normalize_report_text(_li_text_without_nested_li(li)).strip()
                if not block:
                    continue

                # Header must belong to the primary CVE and carry critical + 9.0..10.0.
                hm = re.match(
                    r'^\\s*' + re.escape(primary) +
                    r'\\s*\\(\\s*(?:krytyczne|krytyczna|krytyczny|critical)\\s*,\\s*'
                    r'(?:CVSS(?:\\s*v?[234](?:[.,]\\d|\\.x)?)?(?:\\s+Base\\s+Score)?\\s*[:=]?\\s*)?'
                    r'(10(?:[.,]0)?|9(?:[.,][0-9]+)?)\\s*\\)\\s*:?',
                    block,
                    re.I,
                )
                if hm:
                    try:
                        score = float(hm.group(1).replace(',', '.'))
                    except Exception:
                        score = None
                    if score is not None and 9.0 <= score <= 10.0:
                        count += 1
            return count

        if ext == '.pdf':
            text = read_pdf_text(path)
            if not text.strip():
                return 0
            severity_token = r'krytyczne|krytyczna|krytyczny|critical'
            score_token = r'10(?:[.,]0)?|9(?:[.,][0-9]+)?'
            header_re = re.compile(
                rf'(?im)^[ \\t]*(?:[•·‣◦▪●○►▸➤➜*-]+[ \\t]*)?'
                rf'CVE-\\d{{4}}-\\d{{4,}}[ \\t]*(?:\\n[ \\t]*)?'
                rf'\\(\\s*(?:{severity_token})\\s*,\\s*'
                rf'(?:CVSS(?:\\s*v?[234](?:[.,]\\d|\\.x)?)?(?:\\s+Base\\s+Score)?\\s*[:=]?\\s*)?'
                rf'(?P<score>{score_token})\\s*\\)\\s*:?',
                re.I | re.M,
            )
            return sum(
                1 for m in header_re.finditer(text)
                if 9.0 <= float(m.group('score').replace(',', '.')) <= 10.0
            )
    except Exception:
        return 0
    return 0


def audit_critical_counts_by_folder_and_class(
    all_detail: pd.DataFrame,
    class_map: Optional[Dict[str, str]] = None,
    log_fp=None,
) -> None:
    """
    Log exact critical-occurrence distribution by source folder and PK/PI/PP.

    This makes mapping problems visible. Example:
        PGZ: total critical=73 | PK=0 | PI=0 | PP=73 | UNCLASSIFIED=0

    If total=73 but PP=20 and UNCLASSIFIED=53, the parser is fine and the
    remaining issue is the PK/PI/PP domain mapping workbook.
    """
    prepared = _prepare_cve_frame(all_detail, class_map)
    findings = _logical_cve_finding_frame(prepared)

    if findings.empty:
        log_line("[*] CRITICAL FOLDER AUDIT: no CVE findings.", log_fp)
        return

    if "Folder" not in findings.columns:
        findings["Folder"] = ""

    findings["__critical"] = findings.apply(is_critical_record, axis=1)

    for folder, g in findings.groupby("Folder", dropna=False, sort=True):
        crit = g[g["__critical"]].copy()
        total = int(len(crit))

        counts = {}
        for code_ in PRESENTATION_CLASSES:
            counts[code_] = int(
                (crit["PresentationClass"] == code_).sum()
            )

        unclassified = int(
            (~crit["PresentationClass"].isin(PRESENTATION_CLASSES)).sum()
        )

        log_line(
            f"[*] CRITICAL FOLDER AUDIT {folder or '(no folder)'}: "
            f"critical_occurrences={total}, "
            f"PK={counts['PK']}, PI={counts['PI']}, PP={counts['PP']}, "
            f"UNCLASSIFIED={unclassified}, "
            f"CLASS_SUM={counts['PK'] + counts['PI'] + counts['PP']}",
            log_fp,
        )

        if unclassified != 0 or (
            counts["PK"] + counts["PI"] + counts["PP"]
        ) != total:
            raise RuntimeError(
                f"Critical folder classification failed for {folder}: "
                f"total={total}, PK={counts['PK']}, PI={counts['PI']}, "
                f"PP={counts['PP']}, unclassified={unclassified}"
            )


def process_folder(folder: str, log_fp, group_map: Dict[str, str], folder_label: Optional[str] = None):
    folder_name = folder_label or os.path.basename(os.path.normpath(folder))
    log_line(f"\n=== Processing folder: {folder_name} ===", log_fp)
    # Case-insensitive report discovery inside this source folder.
    # Supported inputs: HTML, HTM and text-based PDF.
    # Discover candidate report files. HTML/HTM is authoritative when the same
    # report also exists as PDF. This prevents one logical report from being
    # counted twice (e.g. 57 HTML critical findings + the same 57 in PDF = 114).
    candidates = sorted(
        os.path.join(folder, name)
        for name in os.listdir(folder)
        if os.path.isfile(os.path.join(folder, name))
        and name.lower().endswith((".html", ".htm", ".pdf"))
    )
    if not candidates:
        log_line("[!] No HTML/HTM/PDF reports, skipping.", log_fp)
        return None

    # 1) Same basename/stem in HTML and PDF -> keep HTML/HTM only.
    by_stem = defaultdict(list)
    for pth in candidates:
        stem = os.path.splitext(os.path.basename(pth))[0].lower()
        by_stem[stem].append(pth)

    report_files = []
    for stem, paths in sorted(by_stem.items()):
        htmls = [p for p in paths if os.path.splitext(p)[1].lower() in (".html", ".htm")]
        if htmls:
            report_files.extend(sorted(htmls))
            skipped = [p for p in paths if p not in htmls]
            for p in skipped:
                log_line(
                    f"    [dedupe-source] skipping PDF duplicate because HTML/HTM exists: {os.path.basename(p)}",
                    log_fp,
                )
        else:
            report_files.extend(sorted(paths))

    # IMPORTANT: never deduplicate different report filenames merely because
    # their normalized content is identical. In EASM, two different domain
    # reports can legitimately contain exactly the same findings. Treating
    # identical content as a duplicate would silently drop affected entities
    # (e.g. 9 SameSite reports becoming 4).
    #
    # HTML/PDF duplicates of the SAME basename were already handled above.
    # Therefore every remaining filename is an independent reporting asset.
    report_files = list(report_files)

    cve_rows: List[Dict[str, str]] = []
    cfg_rows: List[Dict[str, str]] = []
    all_rows: List[Dict[str, str]] = []
    raw_cve_occurrences_total = 0
    raw_critical_occurrences_total = 0
    native_critical_headers_total = 0

    for path in report_files:
        domain = normalize_domain_key(os.path.splitext(os.path.basename(path))[0])
        if not domain:
            domain = os.path.splitext(os.path.basename(path))[0].lower()
        file_cves = []
        file_cfg = []
        file_all = []

        raw_cve_count, raw_critical_count = raw_critical_occurrences_in_report(path)
        native_critical_count = native_critical_headers_in_report(path)
        raw_cve_occurrences_total += raw_cve_count
        raw_critical_occurrences_total += raw_critical_count
        native_critical_headers_total += native_critical_count

        try:
            file_cves = extract_cve_records(path, domain, group_map)
            cve_rows.extend(file_cves)
        except Exception as e:
            log_line(
                f"[!] CVE extraction failed for {path}: {type(e).__name__}: {e}",
                log_fp,
            )

        try:
            file_cfg = extract_config_records(path, domain, group_map)
            cfg_rows.extend(file_cfg)
            audit_config_detection_for_file(path, domain, file_cfg, log_fp)
        except Exception as e:
            log_line(
                f"[!] CONFIG extraction failed for {path}: {type(e).__name__}: {e}",
                log_fp,
            )

        try:
            file_all = extract_all_finding_blocks(path, domain, group_map)
            all_rows.extend(file_all)
        except Exception as e:
            log_line(
                f"[!] ALL-FINDINGS extraction failed for {path}: {type(e).__name__}: {e}",
                log_fp,
            )

        parsed_critical_file = sum(
            1 for r in file_cves if is_critical_record(r)
        )
        log_line(
            f"    [file] {os.path.basename(path)} -> "
            f"RAW_CVE_OCCURRENCES={raw_cve_count}, "
            f"RAW_CRITICAL={raw_critical_count}, "
            f"NATIVE_CRITICAL_HEADERS={native_critical_count}, "
            f"PARSED_CVE={len(file_cves)}, "
            f"PARSED_CRITICAL={parsed_critical_file}, "
            f"CONFIG={len(file_cfg)}, RAW_BLOCKS={len(file_all)}",
            log_fp,
        )

    cve_cols = ["CVE", "IP", "Domain", "Group", "Services", "Severity", "CVSS", "Description", "Recommendation", "Source File", "Source Path", "Occurrence ID", "Raw Finding"]
    cfg_cols = ["Description", "Domain", "Group", "Affected Domains", "Affected IPs", "URLs/Resources", "Details", "Source File", "Finding Fingerprint"]
    all_cols = ["Type", "Domain", "Group", "CVEs", "Affected Domains", "Affected IPs", "URLs/Resources", "Details", "Source File"]

    # Preserve every source occurrence. The old CVE+Domain+IP dedupe was the
    # reason folders with e.g. 73 critical entries could be reduced to ~20.
    detail_df = pd.DataFrame(cve_rows, columns=cve_cols) if cve_rows else pd.DataFrame(columns=cve_cols)
    if not detail_df.empty and "Occurrence ID" in detail_df.columns:
        detail_df = detail_df.drop_duplicates(subset=["Occurrence ID"], keep="first").reset_index(drop=True)
    config_detail_df = pd.DataFrame(cfg_rows, columns=cfg_cols).drop_duplicates(subset=["Description", "Domain", "Finding Fingerprint"], keep="first") if cfg_rows else pd.DataFrame(columns=cfg_cols)

    # FINAL SAFETY FILTER: Config_* must not contain CVE identifiers.
    if not config_detail_df.empty:
        cve_mask = pd.Series(False, index=config_detail_df.index)
        for col in ["Description", "Details", "URLs/Resources"]:
            if col in config_detail_df.columns:
                vals = config_detail_df[col].fillna("").astype(str)
                cve_mask = cve_mask | vals.str.contains(CVE_RE.pattern, case=False, regex=True)
        config_detail_df = config_detail_df.loc[~cve_mask].copy().reset_index(drop=True)

        # Known canonical configuration categories have already been validated
        # by extract_config_records(). Do not apply the broad product-
        # vulnerability prose filter here: it used to delete valid Config_* rows.
        config_detail_df["Details"] = config_detail_df["Details"].fillna("").astype(str).map(strip_excluded_config_lines)
        config_detail_df["Description"] = config_detail_df.apply(
            lambda r: canonical_config_description(r.get("Description", ""), r.get("Details", "")),
            axis=1,
        )
        config_detail_df = config_detail_df[
            config_detail_df["Description"].fillna("").astype(str).str.strip() != ""
        ].copy().reset_index(drop=True)
        config_detail_df = config_detail_df.loc[
            ~config_detail_df["Description"].fillna("").astype(str).map(is_hard_excluded_config_text)
        ].copy().reset_index(drop=True)

        # Never allow generic noise labels into Config_* output.
        noise_mask = config_detail_df["Description"].fillna("").astype(str).apply(
            lambda x: is_meaningless_config_label(x) or bool(
                re.fullmatch(r"(?:Ostrzeżenie|Ostrzezenie|Warning)\s*: ?", str(x).strip(), re.I)
            )
        )
        config_detail_df = config_detail_df.loc[~noise_mask].copy().reset_index(drop=True)

    # One logical configuration vulnerability per category + domain.
    # Repeated endpoints/URLs/findings within the same domain remain evidence,
    # but do not multiply Count.
    if not config_detail_df.empty:
        config_detail_df = dedupe_config_by_domain_category(config_detail_df)
        # A bare warning heading is never a configuration vulnerability.
        _warn_re = r"(?i)^\s*(?:ostrzeżenie|ostrzezenie|warning)\s*[:.!-]?\s*$"
        config_detail_df = config_detail_df.loc[
            ~config_detail_df["Description"].fillna("").astype(str).str.match(_warn_re)
        ].copy().reset_index(drop=True)

    all_findings_df = pd.DataFrame(all_rows, columns=all_cols).drop_duplicates() if all_rows else pd.DataFrame(columns=all_cols)

    if not detail_df.empty:
        detail_df = detail_df.sort_values(["CVE", "Domain", "IP"], kind="stable").reset_index(drop=True)
    if not config_detail_df.empty:
        config_detail_df = config_detail_df.sort_values(["Description", "Domain"], kind="stable").reset_index(drop=True)

    agg_df = aggregate_cves(detail_df)
    config_df = aggregate_config(config_detail_df)

    parsed_critical_total = (
        int(detail_df.apply(is_critical_record, axis=1).sum())
        if not detail_df.empty else 0
    )

    log_line(f"[+] Report files (HTML/HTM/PDF): {len(report_files)}", log_fp)
    log_line(f"[+] Raw CVE occurrences: {raw_cve_occurrences_total}", log_fp)
    log_line(f"[+] Raw/parser critical occurrences (primary finding CVSS 9.0-10.0): {raw_critical_occurrences_total}", log_fp)
    log_line(f"[+] Native explicit critical headers (diagnostic): {native_critical_headers_total}", log_fp)
    log_line(f"[+] Parsed CVE occurrence rows: {len(detail_df)}", log_fp)
    log_line(f"[+] Parsed critical occurrences (primary finding CVSS 9.0-10.0): {parsed_critical_total}", log_fp)
    duplicate_occ = int(detail_df["Occurrence ID"].duplicated().sum()) if (not detail_df.empty and "Occurrence ID" in detail_df.columns) else 0
    log_line(f"[+] Duplicate source Occurrence IDs after normalization: {duplicate_occ}", log_fp)
    log_line(f"[+] Unique CVEs: {detail_df['CVE'].nunique() if not detail_df.empty else 0}", log_fp)

    if len(detail_df) != raw_cve_occurrences_total:
        msg = (
            f"CVE OCCURRENCE COUNT MISMATCH in {folder_name}: "
            f"raw={raw_cve_occurrences_total}, parsed={len(detail_df)}. "
            "The same authoritative parser produced different totals between audit and extraction. "
            "Check the per-file RAW/PARSED log lines; generation is aborted."
        )
        log_line(f"[!] {msg}", log_fp)
        raise RuntimeError(msg)

    if parsed_critical_total != raw_critical_occurrences_total:
        msg = (
            f"CRITICAL COUNT MISMATCH in {folder_name}: "
            f"raw={raw_critical_occurrences_total}, parsed={parsed_critical_total}. "
            "Dashboard generation is aborted so critical findings cannot be silently omitted."
        )
        log_line(f"[!] {msg}", log_fp)
        raise RuntimeError(msg)
    log_line(f"[+] Config/domain detailed rows: {len(config_detail_df)}", log_fp)
    log_line(f"[+] Preserved top-level finding blocks: {len(all_findings_df)}", log_fp)

    # Do not skip folders that have only configuration findings.
    if detail_df.empty and config_detail_df.empty and all_findings_df.empty:
        return None
    return folder_name, detail_df, agg_df, config_df, config_detail_df, all_findings_df


def build_all_data_frames(results):
    det, stats, cfg, cfgdet, allf = [], [], [], [], []
    for folder, detail_df, agg_df, config_df, config_detail_df, all_findings_df in results:
        if not detail_df.empty:
            x = detail_df.copy(); x.insert(0, "Folder", folder.upper()); det.append(x)
        if not agg_df.empty:
            x = agg_df.copy(); x.insert(0, "Folder", folder.upper()); stats.append(x)
        if not config_df.empty:
            x = config_df.copy(); x.insert(0, "Folder", folder.upper()); cfg.append(x)
        if not config_detail_df.empty:
            x = config_detail_df.copy(); x.insert(0, "Folder", folder.upper()); cfgdet.append(x)
        if not all_findings_df.empty:
            x = all_findings_df.copy(); x.insert(0, "Folder", folder.upper()); allf.append(x)

    all_detail = pd.concat(det, ignore_index=True) if det else pd.DataFrame(columns=["Folder", "CVE", "IP", "Domain", "Group", "Services", "Severity", "CVSS", "Description", "Recommendation", "Source File", "Source Path", "Occurrence ID", "Raw Finding"])
    # Global guard: the same physical source occurrence may appear only once in
    # the combined dataframe. Different <li> entries have different Occurrence IDs
    # and therefore remain separate findings.
    if not all_detail.empty and "Occurrence ID" in all_detail.columns:
        before_n = len(all_detail)
        all_detail = all_detail.drop_duplicates(subset=["Occurrence ID"], keep="first").reset_index(drop=True)
    all_stats = pd.concat(stats, ignore_index=True) if stats else pd.DataFrame(columns=["Folder", "CVE", "Statistics", "Domains", "Group", "IP", "Services", "Severity", "CVSS"])
    all_cfg = pd.concat(cfg, ignore_index=True) if cfg else pd.DataFrame(columns=["Folder", "Description", "Count", "Domains", "Group"])
    all_cfg_detail = pd.concat(cfgdet, ignore_index=True) if cfgdet else pd.DataFrame(columns=["Folder", "Description", "Domain", "Group", "Affected Domains", "Affected IPs", "URLs/Resources", "Details", "Source File", "Finding Fingerprint"])
    all_findings = pd.concat(allf, ignore_index=True) if allf else pd.DataFrame(columns=["Folder", "Type", "Domain", "Group", "CVEs", "Affected Domains", "Affected IPs", "URLs/Resources", "Details", "Source File"])
    return all_detail, all_stats, all_cfg, all_cfg_detail, all_findings


def build_konfiguracyjne_all_aggregated(
    all_cfg_detail: pd.DataFrame,
    group_map: Dict[str, str],
) -> pd.DataFrame:
    """
    Build the global configuration table using one logical occurrence per
    category + reporting/main domain.

    Affected subdomains are retained in All_Config_Detailed as evidence but do
    not multiply Count here.
    """
    if all_cfg_detail is None or all_cfg_detail.empty:
        return pd.DataFrame(columns=["Description", "Count", "Domains", "Group"])

    df = dedupe_config_by_domain_category(all_cfg_detail)
    if df.empty:
        return pd.DataFrame(columns=["Description", "Count", "Domains", "Group"])

    rows = []
    for desc, g in df.groupby("Description", dropna=False):
        domains_list = sorted({
            _config_main_domain(r)
            for _, r in g.iterrows()
            if _config_main_domain(r)
        })
        domains = ", ".join(domains_list)
        rows.append({
            "Description": desc,
            "Count": len(domains_list),
            "Domains": domains,
            "Group": groups_for_domain_csv(domains, group_map),
        })

    return (
        pd.DataFrame(rows)
        .sort_values(["Count", "Description"], ascending=[False, True], kind="stable")
        .reset_index(drop=True)
    )


# ---------------------------------------------------------------------------
# State / history model
# ---------------------------------------------------------------------------

# Identity tuples:
# CVE    -> ("CVE", FOLDER, DOMAIN, CVE)
# CONFIG -> ("CONFIG", FOLDER, DOMAIN, DESCRIPTION)

def cve_identity(folder: str, domain: str, cve: str) -> Tuple[str, str, str, str]:
    return ("CVE", _norm(folder).upper(), normalize_domain_key(domain), _norm(cve).upper())


def cfg_identity(folder: str, domain: str, desc: str) -> Tuple[str, str, str, str]:
    canonical = canonical_config_description(_norm(desc), "")
    return (
        "CONFIG",
        _norm(folder).upper(),
        normalize_domain_key(domain),
        re.sub(r"\s+", " ", canonical),
    )


def current_state_from_frames(all_detail: pd.DataFrame, all_cfg_detail: pd.DataFrame) -> Dict[Tuple[str, str, str, str], Dict[str, str]]:
    state: Dict[Tuple[str, str, str, str], Dict[str, str]] = {}

    if not all_detail.empty:
        for _, r in all_detail.iterrows():
            key = cve_identity(r.get("Folder", ""), r.get("Domain", ""), r.get("CVE", ""))
            if not key[2] or not key[3]:
                continue
            meta = state.setdefault(key, {"IPs": "", "Group": "", "Details": ""})
            meta["IPs"] = stable_join([meta.get("IPs", ""), _norm(r.get("IP", ""))])
            meta["Group"] = stable_join([meta.get("Group", ""), _norm(r.get("Group", ""))])
            meta["Details"] = _norm(r.get("Description", ""))

    if not all_cfg_detail.empty:
        for _, r in all_cfg_detail.iterrows():
            _cfg_blob = _norm(r.get("Description", "")) + " " + _norm(r.get("Details", ""))
            if CVE_RE.search(_cfg_blob) or looks_like_product_vulnerability_text(_cfg_blob):
                continue
            if not is_explicit_configuration_finding(_cfg_blob):
                continue
            _canon_desc = canonical_config_description(r.get("Description", ""), r.get("Details", ""))
            if not _canon_desc or is_hard_excluded_config_text(_canon_desc):
                continue
            key = cfg_identity(r.get("Folder", ""), r.get("Domain", ""), _canon_desc)
            if not key[2] or not key[3]:
                continue
            meta = state.setdefault(key, {"IPs": "", "Group": "", "Details": ""})
            meta["IPs"] = stable_join([meta.get("IPs", ""), _norm(r.get("Affected IPs", ""))])
            meta["Group"] = stable_join([meta.get("Group", ""), _norm(r.get("Group", ""))])
            meta["Details"] = _norm(r.get("Details", ""))
    return state


def load_state_from_workbook(path: str) -> Dict[Tuple[str, str, str, str], Dict[str, str]]:
    xls = pd.ExcelFile(path)
    state: Dict[Tuple[str, str, str, str], Dict[str, str]] = {}

    # CVE detailed - current and legacy formats.
    if "All_data_detailed" in xls.sheet_names:
        df = pd.read_excel(xls, "All_data_detailed")
        if {"Folder", "CVE", "Domain"}.issubset(df.columns):
            for _, r in df.iterrows():
                key = cve_identity(r.get("Folder", ""), r.get("Domain", ""), r.get("CVE", ""))
                if not key[2] or not key[3]:
                    continue
                meta = state.setdefault(key, {"IPs": "", "Group": "", "Details": ""})
                meta["IPs"] = stable_join([meta["IPs"], _norm(r.get("IP", ""))])
                meta["Group"] = stable_join([meta["Group"], _norm(r.get("Group", ""))])
                meta["Details"] = _norm(r.get("Description", ""))

    # New detailed config format.
    if "All_Config_Detailed" in xls.sheet_names:
        df = pd.read_excel(xls, "All_Config_Detailed")
        if {"Folder", "Description", "Domain"}.issubset(df.columns):
            for _, r in df.iterrows():
                if CVE_RE.search(_norm(r.get("Description", ""))) or CVE_RE.search(_norm(r.get("Details", ""))):
                    continue
                key = cfg_identity(r.get("Folder", ""), r.get("Domain", ""), r.get("Description", ""))
                if not key[2] or not key[3]:
                    continue
                state[key] = {
                    "IPs": _norm(r.get("Affected IPs", "")),
                    "Group": _norm(r.get("Group", "")),
                    "Details": _norm(r.get("Details", "")),
                }
    else:
        # Legacy aggregate config sheets: expand Domains so identity is per domain.
        for sheet in xls.sheet_names:
            if not sheet.endswith("_Config_Issues"):
                continue
            folder = sheet[: -len("_Config_Issues")].upper()
            df = pd.read_excel(xls, sheet)
            if "Description" not in df.columns:
                continue
            for _, r in df.iterrows():
                desc = _norm(r.get("Description", ""))
                if CVE_RE.search(desc) or looks_like_product_vulnerability_text(desc):
                    continue
                if not is_explicit_configuration_finding(desc):
                    continue
                domains = [_norm(x) for x in _norm(r.get("Domains", "")).split(",") if _norm(x)]
                for domain in domains:
                    key = cfg_identity(folder, domain, desc)
                    if key[2] and key[3]:
                        state[key] = {"IPs": "", "Group": _norm(r.get("Group", "")), "Details": ""}
    return state


def discover_previous_workbooks(
    root_folder: str,
    new_basename: str,
    current_ts: datetime,
    log_fp=None,
) -> List[str]:
    """
    Return ALL valid historical combined findings snapshots older than the
    current run, chronologically sorted.

    IMPORTANT:
    - No one-file-per-month reduction is performed.
    - If the folder contains 2 previous findings_all workbooks, both are used.
    - If it contains 10, all 10 are used.
    - Multiple scans from the same month are preserved.

    Calendar-month calculations are handled later by build_history(), where
    distinct months are counted separately from the number of scans.
    """
    current_candidate = os.path.abspath(
        os.path.join(root_folder, new_basename)
    )

    all_paths = discover_snapshot_workbooks(
        root_folder,
        current_candidate if os.path.isfile(current_candidate) else None,
        None,
    )

    result: List[Tuple[datetime, str]] = []

    for path in all_paths:
        path_abs = os.path.abspath(path)

        if path_abs == current_candidate:
            continue

        try:
            ts = parse_workbook_timestamp(path)
        except Exception:
            ts = datetime.fromtimestamp(os.path.getmtime(path))

        # Only snapshots genuinely older than the current execution belong to
        # historical input.
        if ts >= current_ts:
            continue

        result.append((ts, path_abs))

    result.sort(key=lambda x: (x[0], x[1]))
    paths = [p for _, p in result]

    if log_fp is not None:
        log_line(
            f"[*] Historical snapshots selected: {len(paths)} "
            "(ALL valid findings workbooks, no monthly reduction)",
            log_fp,
        )
        for p in paths:
            try:
                ts = parse_workbook_timestamp(p)
                log_line(
                    f"    - {ts.strftime('%Y-%m-%d %H:%M')} | {p}",
                    log_fp,
                )
            except Exception:
                log_line(f"    - {p}", log_fp)

    return paths


def load_history_sheet(path: str) -> Dict[Tuple[str, str, str, str], Dict[str, object]]:
    try:
        xls = pd.ExcelFile(path)
        if "History" not in xls.sheet_names:
            return {}
        df = pd.read_excel(xls, "History")
    except Exception:
        return {}
    out = {}
    required = {"Type", "Folder", "Domain", "Vulnerability"}
    if not required.issubset(df.columns):
        return {}
    for _, r in df.iterrows():
        key = (_norm(r["Type"]).upper(), _norm(r["Folder"]).upper(), normalize_domain_key(r["Domain"]), _norm(r["Vulnerability"]))
        out[key] = {c: r.get(c, "") for c in df.columns}
    return out


def _calendar_month_count(dates: Iterable[datetime]) -> int:
    """Number of distinct YYYY-MM calendar months represented by dates."""
    months = {
        (d.year, d.month)
        for d in dates
        if isinstance(d, datetime)
    }
    return len(months)


def _months_elapsed_floor(start_dt: datetime, end_dt: datetime) -> int:
    """
    Full calendar months elapsed between two timestamps.

    Example:
      2026-01-15 -> 2026-04-15 = 3
      2026-01-31 -> 2026-04-20 = 2
    """
    if not isinstance(start_dt, datetime) or not isinstance(end_dt, datetime):
        return 0
    if end_dt < start_dt:
        return 0

    months = (end_dt.year - start_dt.year) * 12 + (
        end_dt.month - start_dt.month
    )
    if end_dt.day < start_dt.day:
        months -= 1
    elif end_dt.day == start_dt.day and (
        end_dt.hour,
        end_dt.minute,
        end_dt.second,
    ) < (
        start_dt.hour,
        start_dt.minute,
        start_dt.second,
    ):
        months -= 1
    return max(0, months)


def _month_key(dt: datetime) -> Tuple[int, int]:
    return (dt.year, dt.month)


def _consecutive_months_from_presence(
    present_times: List[datetime],
    all_snapshot_times: List[datetime],
    active_now: bool,
) -> Tuple[int, Optional[datetime], List[Tuple[int, int]]]:
    """
    Determine the current confirmed month streak.

    A month counts only if at least one supplied findings snapshot exists in
    that calendar month AND the vulnerability is present in at least one
    snapshot for that month.

    Missing months break continuity because there is no evidence that the
    vulnerability was still present during that month.

    Multiple findings workbooks in one month count as ONE month.
    """
    if not active_now or not present_times or not all_snapshot_times:
        return 0, None, []

    scanned_months = sorted({_month_key(ts) for ts in all_snapshot_times})
    present_months = sorted({_month_key(ts) for ts in present_times})

    current_month = _month_key(all_snapshot_times[-1])
    if current_month not in present_months:
        return 0, None, []

    streak_months = [current_month]

    y, m = current_month
    while True:
        prev_month = (y - 1, 12) if m == 1 else (y, m - 1)

        if prev_month not in scanned_months:
            break
        if prev_month not in present_months:
            break

        streak_months.append(prev_month)
        y, m = prev_month

    streak_months.reverse()

    first_month = streak_months[0]
    streak_times = [ts for ts in present_times if _month_key(ts) == first_month]
    streak_since = min(streak_times) if streak_times else None

    return len(streak_months), streak_since, streak_months


def build_history(
    previous_paths: List[str],
    current_state: Dict,
    current_ts: datetime,
) -> pd.DataFrame:
    """
    Reconstruct history from ALL supplied snapshots + current run.

    Strict '>3 months' rule:
      - finding must be active now;
      - it must be confirmed in at least 4 consecutive calendar months;
      - more than 3 full months must have elapsed since the beginning of the
        confirmed streak;
      - a missing month breaks continuity.

    Therefore January + February can NEVER qualify as '>3 months'.
    """
    snapshots: List[Tuple[datetime, Dict, str]] = []

    for path in previous_paths:
        try:
            ts = parse_workbook_timestamp(path)
            state = load_state_from_workbook(path)
            snapshots.append((ts, state, path))
        except Exception:
            continue

    snapshots.sort(key=lambda x: (x[0], x[2]))
    snapshots.append((current_ts, current_state, "__CURRENT__"))

    all_snapshot_times = [ts for ts, _state, _path in snapshots]

    all_keys = set()
    for _, state, _ in snapshots:
        all_keys.update(state.keys())

    rows = []

    for key in sorted(all_keys):
        observations: List[Tuple[datetime, bool, Dict]] = []

        for ts, state, _path in snapshots:
            present = key in state
            meta = state.get(key, {}) if present else {}
            observations.append((ts, present, meta))

        present_times = [ts for ts, present, _meta in observations if present]
        if not present_times:
            continue

        first_seen = min(present_times)
        last_seen = max(present_times)
        active = observations[-1][1]

        confirmed_months, confirmed_streak_since, _streak_months = (
            _consecutive_months_from_presence(
                present_times,
                all_snapshot_times,
                active,
            )
        )

        disappeared_at = ""
        if not active:
            last_present_index = max(
                i for i, (_ts, present, _m) in enumerate(observations)
                if present
            )
            for i in range(last_present_index + 1, len(observations)):
                if not observations[i][1]:
                    disappeared_at = observations[i][0]
                    break

        if active and confirmed_streak_since is not None:
            continuous_age_months = _months_elapsed_floor(
                confirmed_streak_since,
                current_ts,
            )
            streak_since = confirmed_streak_since
        else:
            continuous_age_months = 0
            streak_since = ""

        total_months = len({_month_key(ts) for ts in present_times})
        total_snapshots = len(present_times)

        was_present = observations[-2][1] if len(observations) >= 2 else False
        is_present = observations[-1][1]

        if is_present and not was_present:
            status = STATUS_ADDED
        elif not is_present and was_present:
            status = STATUS_REMOVED
        else:
            status = STATUS_UNCHANGED if is_present else STATUS_REMOVED

        meta = {}
        for _ts, present, candidate_meta in reversed(observations):
            if present:
                meta = candidate_meta or {}
                break

        # Strict threshold. January->April is exactly 3 months, so still False.
        # January->May with Jan/Feb/Mar/Apr/May confirmed is True.
        over_three_months = bool(
            active
            and confirmed_months >= 4
            and continuous_age_months > 3
        )

        rows.append({
            "Type": key[0],
            "Folder": key[1],
            "Domain": key[2],
            "Vulnerability": key[3],
            "Group": meta.get("Group", ""),
            "IPs": meta.get("IPs", ""),
            "First Seen": first_seen,
            "Current Streak Since": streak_since,
            "Last Seen": last_seen,
            "Disappeared At": disappeared_at,
            "Consecutive Months": confirmed_months,
            "Continuous Age Months": continuous_age_months,
            "Total Months Observed": total_months,
            "Total Snapshots Observed": total_snapshots,
            "Over 3 Months": over_three_months,
            "Active": bool(active),
            "Current Status": status,
        })

    columns = [
        "Type",
        "Folder",
        "Domain",
        "Vulnerability",
        "Group",
        "IPs",
        "First Seen",
        "Current Streak Since",
        "Last Seen",
        "Disappeared At",
        "Consecutive Months",
        "Continuous Age Months",
        "Total Months Observed",
        "Total Snapshots Observed",
        "Over 3 Months",
        "Active",
        "Current Status",
    ]

    df = pd.DataFrame(rows, columns=columns)
    if not df.empty:
        df = df.sort_values(
            ["Active", "Type", "Folder", "Domain", "Vulnerability"],
            ascending=[False, True, True, True, True],
            kind="stable",
        ).reset_index(drop=True)

    return df

def build_diff(prev_state: Dict, cur_state: Dict, history_df: pd.DataFrame) -> Tuple[List[str], pd.DataFrame, pd.DataFrame]:
    prev_keys, cur_keys = set(prev_state), set(cur_state)
    added = cur_keys - prev_keys
    removed = prev_keys - cur_keys
    unchanged = cur_keys & prev_keys

    hist_lookup = {}
    if not history_df.empty:
        for _, r in history_df.iterrows():
            key = (_norm(r["Type"]).upper(), _norm(r["Folder"]).upper(), normalize_domain_key(r["Domain"]), _norm(r["Vulnerability"]))
            hist_lookup[key] = r

    cve_rows, cfg_rows = [], []
    for key in sorted(added | removed | unchanged):
        status = STATUS_ADDED if key in added else STATUS_REMOVED if key in removed else STATUS_UNCHANGED
        meta = cur_state.get(key) or prev_state.get(key) or {}
        h = hist_lookup.get(key, {})
        common = {
            "Folder": key[1], "Domain": key[2], "Group": meta.get("Group", ""), "IP": meta.get("IPs", ""),
            "Status Podatnosci": status,
            "First Seen": h.get("First Seen", ""), "Current Streak Since": h.get("Current Streak Since", ""),
            "Last Seen": h.get("Last Seen", ""), "Disappeared At": h.get("Disappeared At", ""),
            "Consecutive Months": h.get("Consecutive Months", ""), "Total Months Observed": h.get("Total Months Observed", ""),
        }
        if key[0] == "CVE":
            cve_rows.append({"CVE": key[3], **common})
        else:
            cfg_rows.append({"Description": key[3], **common})

    cve_df = pd.DataFrame(cve_rows, columns=["Folder", "CVE", "Domain", "Group", "IP", "Status Podatnosci", "First Seen", "Current Streak Since", "Last Seen", "Disappeared At", "Consecutive Months", "Total Months Observed"])
    cfg_df = pd.DataFrame(cfg_rows, columns=["Folder", "Description", "Domain", "Group", "IP", "Status Podatnosci", "First Seen", "Current Streak Since", "Last Seen", "Disappeared At", "Consecutive Months", "Total Months Observed"])

    lines = [
        "diff.txt - findings comparison",
        f"Added: {len(added)}",
        f"Removed: {len(removed)}",
        f"Unchanged: {len(unchanged)}",
        "",
    ]
    for status, keys in [(STATUS_ADDED, added), (STATUS_REMOVED, removed), (STATUS_UNCHANGED, unchanged)]:
        lines.append(f"{status.upper()} ({len(keys)}):")
        for k in sorted(keys):
            lines.append(f"  {k[0]} | {k[1]} | {k[2]} | {k[3]}")
        lines.append("")
    return lines, cve_df, cfg_df


# ---------------------------------------------------------------------------
# Presentation / dashboard helpers
# ---------------------------------------------------------------------------

def _safe_read_sheet(path: Optional[str], sheet_name: str) -> pd.DataFrame:
    if not path or not os.path.isfile(path):
        return pd.DataFrame()
    try:
        xls = pd.ExcelFile(path)
        if sheet_name not in xls.sheet_names:
            return pd.DataFrame()
        return pd.read_excel(xls, sheet_name)
    except Exception:
        return pd.DataFrame()


def _prepare_cve_frame(
    df: pd.DataFrame,
    class_map: Optional[Dict[str, str]] = None,
) -> pd.DataFrame:
    cols = [
        "CVE", "Domain", "Group", "Services", "Severity", "CVSS",
        "Description", "Raw Finding", "Source File", "Source Path", "Occurrence ID",
        "PresentationClass", "PresentationEntity"
    ]
    if df is None or df.empty:
        return pd.DataFrame(columns=cols)

    x = df.copy()
    for col in [
        "CVE", "Domain", "Group", "Services", "Severity", "CVSS",
        "Description", "Raw Finding", "Source File", "Source Path", "Occurrence ID"
    ]:
        if col not in x.columns:
            x[col] = ""

    # Canonical CVE ID prevents one vulnerability from being split by case or
    # formatting differences.
    x["CVE"] = x["CVE"].fillna("").astype(str).map(normalize_cve_id)
    x = x[x["CVE"].astype(str).str.match(r"^CVE-\d{4}-\d{4,}$", case=False, na=False)].copy()

    # Resolve severity and score once using the same rules as critical counting.
    for idx, row in x.iterrows():
        sev, score = effective_severity_and_cvss(row)
        x.at[idx, "Severity"] = sev
        x.at[idx, "CVSS"] = score if score is not None else ""

    x["Domain"] = x["Domain"].fillna("").astype(str).map(normalize_domain_key)

    # Defensive recovery for legacy rows where Domain was not persisted.
    # Report files are normally named after the scanned domain.
    if "Source File" in x.columns:
        blank_domain = x["Domain"].eq("")
        if blank_domain.any():
            recovered = (
                x.loc[blank_domain, "Source File"]
                .fillna("")
                .astype(str)
                .map(lambda s: normalize_domain_key(
                    re.sub(r"\.(?:html?|pdf)$", "", os.path.basename(s), flags=re.I)
                ))
            )
            x.loc[blank_domain, "Domain"] = recovered

    x["PresentationEntity"] = x["Domain"].map(
        lambda d: presentation_entity_for_domain(d, class_map)
    )

    # Final defensive entity fallback. A source-domain finding must not vanish
    # from presentation counts because entity mapping failed.
    blank_entity = x["PresentationEntity"].fillna("").astype(str).str.strip().eq("")
    x.loc[blank_entity, "PresentationEntity"] = x.loc[blank_entity, "Domain"]
    x["PresentationClass"] = x.apply(
        lambda r: presentation_class_for_domain(
            r.get("Domain", ""), r.get("Group", ""), class_map
        ),
        axis=1,
    )
    return x.reset_index(drop=True)



def _logical_cve_finding_frame(df: pd.DataFrame) -> pd.DataFrame:
    """
    Authoritative finding-level frame for TOP5_PK / TOP5_PI / TOP5_PP counts.

    EVERY row from All_data_detailed represents one source CVE occurrence.
    We intentionally do NOT collapse repeated CVE+Domain+IP combinations.

    Critical count rule:
        each preserved source occurrence with primary-finding CVSS 9.0..10.0 contributes +1.

    Occurrence ID is preserved when available. Historical workbooks that do not
    contain it get a deterministic synthetic row ID.
    """
    if df is None or df.empty:
        return pd.DataFrame(columns=list(df.columns) if df is not None else [])

    x = df.copy().reset_index(drop=True)

    for col in [
        "PresentationClass",
        "PresentationEntity",
        "CVE",
        "Domain",
        "IP",
        "CVSS",
        "Severity",
        "Source File",
        "Source Path",
        "Occurrence ID",
    ]:
        if col not in x.columns:
            x[col] = ""

    x["CVE"] = x["CVE"].fillna("").astype(str).map(normalize_cve_id)
    x["Domain"] = x["Domain"].fillna("").astype(str).map(normalize_domain_key)
    x["IP"] = x["IP"].fillna("").astype(str).str.strip()

    x = x[
        (x["PresentationEntity"].fillna("").astype(str).str.strip() != "")
        & (x["CVE"].fillna("").astype(str).str.strip() != "")
    ].copy().reset_index(drop=True)

    if x.empty:
        return x

    # Resolve severity from CVSS for every individual occurrence.
    for idx, row in x.iterrows():
        sev, score = effective_severity_and_cvss(row)
        x.at[idx, "Severity"] = sev
        x.at[idx, "CVSS"] = score if score is not None else ""

        occ = str(row.get("Occurrence ID", "") or "").strip()
        if not occ:
            source = str(row.get("Source File", "") or "").strip()
            x.at[idx, "Occurrence ID"] = (
                f"{source or 'historical'}::row::{idx + 1:08d}"
            )

    # One physical source occurrence may be counted only once. Different LI
    # entries keep different IDs even for identical CVE/domain/IP values.
    x["Occurrence ID"] = x["Occurrence ID"].fillna("").astype(str).str.strip()
    with_id = x[x["Occurrence ID"] != ""].drop_duplicates(subset=["Occurrence ID"], keep="first")
    without_id = x[x["Occurrence ID"] == ""]
    x = pd.concat([with_id, without_id], ignore_index=True)

    return x.reset_index(drop=True)


def _logical_cve_entity_frame(df: pd.DataFrame) -> pd.DataFrame:
    """
    Collapse CVE evidence to one logical vulnerability per reporting entity.

    Identity:
        PresentationClass + PresentationEntity + CVE

    A CVE exposed on root + several subdomains of the same entity counts once.
    For conflicting evidence the highest valid CVSS / severity wins.
    """
    if df is None or df.empty:
        return pd.DataFrame(columns=list(df.columns) if df is not None else [])

    x = df.copy()
    required = ["PresentationClass", "PresentationEntity", "CVE"]
    for col in required:
        if col not in x.columns:
            x[col] = ""

    x = x[
        (x["PresentationEntity"].fillna("").astype(str).str.strip() != "")
        & (x["CVE"].fillna("").astype(str).str.strip() != "")
    ].copy()

    if x.empty:
        return x

    rows = []
    for (_cls, _entity, _cve), g in x.groupby(
        ["PresentationClass", "PresentationEntity", "CVE"],
        dropna=False,
        sort=False,
    ):
        g = g.copy()

        # Enrich temporary ranking columns.
        g["__cvss"] = g["CVSS"].map(_valid_cvss_number)
        g["__sev_rank"] = g["Severity"].map(severity_rank)
        g["__crit"] = g.apply(is_critical_record, axis=1).astype(int)

        # Pick the strongest/richest representative row.
        def _row_rank(row):
            cv = row.get("__cvss")
            cv_num = float(cv) if cv is not None and not pd.isna(cv) else -1.0
            richness = sum(
                len(str(row.get(c, "") or "").strip())
                for c in ("Description", "Raw Finding", "Services")
            )
            return (
                int(row.get("__crit", 0)),
                int(row.get("__sev_rank", 0)),
                cv_num,
                richness,
            )

        best_idx = max(g.index, key=lambda idx: _row_rank(g.loc[idx]))
        row = g.loc[best_idx].copy()

        valid_scores = [
            s for s in g["__cvss"].tolist()
            if s is not None and not pd.isna(s)
        ]
        group_has_critical = bool(g["__crit"].astype(int).max())
        if valid_scores:
            max_score = max(float(s) for s in valid_scores)
            row["CVSS"] = max_score
            if group_has_critical or max_score >= 9.0:
                row["Severity"] = "critical"
            elif max_score >= 7.0:
                row["Severity"] = "high"
            elif max_score >= 4.0:
                row["Severity"] = "medium"
            elif max_score > 0:
                row["Severity"] = "low"
            else:
                row["Severity"] = "unknown"
        else:
            # Preserve explicit critical/high/etc. evidence even if a historical
            # workbook did not contain a numeric CVSS value.
            row["Severity"] = (
                "critical" if group_has_critical
                else normalize_severity(row.get("Severity", ""))
            )
            row["CVSS"] = ""

        # Preserve union of service evidence for product hinting.
        if "Services" in g.columns:
            row["Services"] = stable_join(g["Services"].astype(str))

        for temp in ("__cvss", "__sev_rank", "__crit"):
            if temp in row.index:
                row = row.drop(labels=[temp])

        rows.append(row)

    return pd.DataFrame(rows).reset_index(drop=True)


def _prepare_cfg_frame(df: pd.DataFrame, class_map: Optional[Dict[str, str]] = None) -> pd.DataFrame:
    cols = ["Description", "Domain", "Group", "PresentationClass", "PresentationEntity"]
    if df is None or df.empty:
        return pd.DataFrame(columns=cols)

    x = df.copy()
    for col in ["Description", "Domain", "Group", "Details"]:
        if col not in x.columns:
            x[col] = ""

    x["Details"] = x["Details"].fillna("").astype(str).map(strip_excluded_config_lines)
    x["Description"] = x.apply(
        lambda r: canonical_config_description(r.get("Description", ""), r.get("Details", "")),
        axis=1,
    )
    x = x.loc[
        (x["Description"].fillna("").astype(str).str.strip() != "")
        & (~x["Description"].fillna("").astype(str).map(is_hard_excluded_config_text))
    ].copy()

    x["PresentationEntity"] = x["Domain"].fillna("").astype(str).map(
        lambda d: presentation_entity_for_domain(d, class_map)
    )
    x["PresentationClass"] = x.apply(
        lambda r: presentation_class_for_domain(
            r.get("Domain", ""), r.get("Group", ""), class_map
        ),
        axis=1,
    )
    return x


def _format_count_delta(current: int, previous: int) -> str:
    delta = int(current) - int(previous)
    if delta > 0:
        return f"{int(current)} (+{delta})"
    if delta < 0:
        return f"{int(current)} ({delta})"
    return f"{int(current)} (0)"


def _product_hint_for_cve(rows: pd.DataFrame) -> str:
    """Use only product/service information present in source reports; never guess."""
    if rows is None or rows.empty or "Services" not in rows.columns:
        return "brak danych"
    candidates = []
    for value in rows["Services"].fillna("").astype(str):
        for part in value.split(","):
            p = re.sub(r"\s+", " ", part).strip()
            if p and p.lower() not in {"none", "nan"}:
                candidates.append(p)
    if not candidates:
        return "brak danych"
    counts = pd.Series(candidates).value_counts()
    return str(counts.index[0])[:60]


def _history_for_presentation_entity(
    history_df: pd.DataFrame,
    entity_domain: str,
    class_code: str,
    class_map: Optional[Dict[str, str]] = None,
) -> pd.DataFrame:
    if history_df is None or history_df.empty:
        return pd.DataFrame()

    h = history_df.copy()
    for col in [
        "Domain", "Group", "Current Status", "Active", "First Seen",
        "Consecutive Months", "Vulnerability", "Type"
    ]:
        if col not in h.columns:
            h[col] = ""

    h["_PresentationEntity"] = h["Domain"].fillna("").astype(str).map(
        lambda d: presentation_entity_for_domain(d, class_map)
    )
    h["_PresentationClass"] = h.apply(
        lambda r: presentation_class_for_domain(
            r.get("Domain", ""), r.get("Group", ""), class_map
        ),
        axis=1,
    )

    return h[
        (h["_PresentationEntity"] == normalize_domain_key(entity_domain))
        & (h["_PresentationClass"] == class_code)
    ].copy()


def _current_status_counts(
    history_df: pd.DataFrame,
    domain: str,
    class_code: str,
    class_map: Optional[Dict[str, str]] = None,
) -> Tuple[int, int, str]:
    h = _history_for_presentation_entity(history_df, domain, class_code, class_map)
    if h.empty:
        return 0, 0, ""

    added = int((h["Current Status"].astype(str) == STATUS_ADDED).sum())
    removed = int((h["Current Status"].astype(str) == STATUS_REMOVED).sum())

    active_h = h[h["Active"].astype(str).str.lower().isin(["true", "1", "yes"])]
    first_seen = ""
    if not active_h.empty:
        dates = pd.to_datetime(active_h["First Seen"], errors="coerce").dropna()
        if not dates.empty:
            first_seen = dates.min().strftime("%Y-%m-%d")
    return added, removed, first_seen


def _active_over_three_months(
    history_df: pd.DataFrame,
    domain: str,
    class_code: str,
    class_map: Optional[Dict[str, str]] = None,
) -> int:
    """
    Count unique active vulnerabilities CONFIRMED for more than 3 months.

    Requirements:
      - active now;
      - at least 4 consecutive calendar months with actual scan evidence;
      - more than 3 full elapsed months.

    January + February can never qualify.
    """
    h = _history_for_presentation_entity(
        history_df,
        domain,
        class_code,
        class_map,
    )
    if h.empty:
        return 0

    active_mask = (
        h["Active"]
        .astype(str)
        .str.lower()
        .isin(["true", "1", "yes"])
    )

    if "Over 3 Months" in h.columns:
        over_mask = (
            h["Over 3 Months"]
            .astype(str)
            .str.lower()
            .isin(["true", "1", "yes"])
        )
    else:
        consecutive = pd.to_numeric(
            h.get("Consecutive Months", 0),
            errors="coerce",
        ).fillna(0)
        age = pd.to_numeric(
            h.get("Continuous Age Months", 0),
            errors="coerce",
        ).fillna(0)
        over_mask = (consecutive >= 4) & (age > 3)

    old_h = h[active_mask & over_mask].copy()
    if old_h.empty:
        return 0

    if {"Type", "Vulnerability"}.issubset(old_h.columns):
        return int(
            old_h[["Type", "Vulnerability"]]
            .fillna("")
            .astype(str)
            .drop_duplicates()
            .shape[0]
        )

    return int(old_h.shape[0])


def build_presentation_data(
    all_detail: pd.DataFrame,
    all_cfg_detail: pd.DataFrame,
    history_df: pd.DataFrame,
    prev_path: Optional[str],
    class_code: str,
    class_map: Optional[Dict[str, str]] = None,
):
    # Raw prepared rows retain source Domain/IP.
    cur_prepared = _prepare_cve_frame(all_detail, class_map)
    prev_prepared = _prepare_cve_frame(
        _safe_read_sheet(prev_path, "All_data_detailed"),
        class_map,
    )

    # FINDING-LEVEL frames are authoritative for COUNTS.
    cur_findings = _logical_cve_finding_frame(cur_prepared)
    prev_findings = _logical_cve_finding_frame(prev_prepared)

    # ENTITY+CVE frame is retained only where one unique CVE per entity is
    # semantically required (e.g. number of affected entities for a CVE).
    cur_entity_cve = _logical_cve_entity_frame(cur_prepared)
    prev_entity_cve = _logical_cve_entity_frame(prev_prepared)

    cur_cfg = _prepare_cfg_frame(all_cfg_detail, class_map)
    prev_cfg = _prepare_cfg_frame(
        _safe_read_sheet(prev_path, "All_Config_Detailed"),
        class_map,
    )

    cur_findings = cur_findings[
        cur_findings["PresentationClass"] == class_code
    ].copy()
    prev_findings = prev_findings[
        prev_findings["PresentationClass"] == class_code
    ].copy()

    cur_entity_cve = cur_entity_cve[
        cur_entity_cve["PresentationClass"] == class_code
    ].copy()
    prev_entity_cve = prev_entity_cve[
        prev_entity_cve["PresentationClass"] == class_code
    ].copy()

    cur_cfg = cur_cfg[
        cur_cfg["PresentationClass"] == class_code
    ].copy()
    prev_cfg = prev_cfg[
        prev_cfg["PresentationClass"] == class_code
    ].copy()

    entities = sorted(
        set(cur_findings["PresentationEntity"].dropna().astype(str))
        | set(cur_cfg["PresentationEntity"].dropna().astype(str))
    )
    entities = [e for e in entities if e]

    entity_rows = []

    for entity in entities:
        cc = cur_findings[
            cur_findings["PresentationEntity"].astype(str) == entity
        ].copy()
        pc = prev_findings[
            prev_findings["PresentationEntity"].astype(str) == entity
        ].copy()

        cg = cur_cfg[
            cur_cfg["PresentationEntity"].astype(str) == entity
        ].copy()
        pg = prev_cfg[
            prev_cfg["PresentationEntity"].astype(str) == entity
        ].copy()

        # CRITICAL = every preserved source CVE occurrence explicitly critical OR CVSS >= 9.0.
        cur_critical = (
            int(cc.apply(is_critical_record, axis=1).sum())
            if not cc.empty else 0
        )
        prev_critical = (
            int(pc.apply(is_critical_record, axis=1).sum())
            if not pc.empty else 0
        )

        # High follows the same finding-level semantics.
        cur_high = (
            int(
                cc.apply(
                    lambda r: (
                        (lambda sev_score: (
                            sev_score[1] is not None
                            and 7.0 <= sev_score[1] < 9.0
                        ))(effective_severity_and_cvss(r))
                    ),
                    axis=1,
                ).sum()
            )
            if not cc.empty else 0
        )

        # Total CVE findings in TOP entity statistics = affected finding records,
        # not unique CVE names.
        cur_all_cves = int(len(cc))

        # Keep a second metric internally for deterministic/auditable ranking.
        cur_unique_cves = (
            int(cc["CVE"].nunique())
            if not cc.empty else 0
        )

        scores = (
            pd.to_numeric(cc["CVSS"], errors="coerce").dropna()
            if not cc.empty
            else pd.Series(dtype=float)
        )
        max_cvss = float(scores.max()) if not scores.empty else -1.0

        # Config categories count once per reporting entity.
        cur_config = (
            int(cg["Description"].dropna().astype(str).nunique())
            if not cg.empty else 0
        )
        prev_config = (
            int(pg["Description"].dropna().astype(str).nunique())
            if not pg.empty else 0
        )

        stale = _active_over_three_months(
            history_df,
            entity,
            class_code,
            class_map,
        )

        # Delta identity for CVE findings includes source Domain and IP.
        def finding_ids(frame):
            if frame is None or frame.empty:
                return set()
            return {
                "CVE:"
                + normalize_cve_id(r.get("CVE", ""))
                + "|DOMAIN:"
                + normalize_domain_key(r.get("Domain", ""))
                + "|IP:"
                + str(r.get("IP", "") or "").strip()
                for _, r in frame.iterrows()
                if normalize_cve_id(r.get("CVE", ""))
            }

        cur_ids = (
            finding_ids(cc)
            | {
                f"CONFIG:{x}"
                for x in cg["Description"].dropna().astype(str)
            }
        )
        prev_ids = (
            finding_ids(pc)
            | {
                f"CONFIG:{x}"
                for x in pg["Description"].dropna().astype(str)
            }
        )

        added = len(cur_ids - prev_ids)
        removed = len(prev_ids - cur_ids)

        _, _, first_seen = _current_status_counts(
            history_df,
            entity,
            class_code,
            class_map,
        )

        # Uwagi: always show exactly the three requested values.
        # "najstarsze od" = oldest currently active vulnerability for the entity.
        oldest_display = "brak"
        if first_seen:
            try:
                _oldest_dt = pd.to_datetime(first_seen, errors="coerce")
                if not pd.isna(_oldest_dt):
                    oldest_display = _oldest_dt.strftime("%d-%m-%Y")
            except Exception:
                oldest_display = str(first_seen)

        notes = [
            f"nowe: {added}",
            f"usuniete: {removed}",
            f"najstarsze od: {oldest_display}",
        ]

        entity_rows.append({
            "Podmiot": entity,
            "Critical": cur_critical,
            "Critical Display": _format_count_delta(
                cur_critical,
                prev_critical,
            ),
            "High": cur_high,
            "All CVE": cur_all_cves,
            "Unique CVE": cur_unique_cves,
            "Max CVSS": max_cvss,
            "Config": cur_config,
            "Config Display": _format_count_delta(
                cur_config,
                prev_config,
            ),
            "Over3": stale,
            "Uwagi": "; ".join(notes),
            "Total": cur_all_cves + cur_config,
        })

    # TOP5 entities:
    #   1) number of critical FINDINGS
    #   2) highest CVSS
    #   3) number of high FINDINGS
    #   4) all CVE FINDINGS
    #   5) unique CVE count
    #   6) config categories
    #   7) active >3 months
    entity_rows.sort(
        key=lambda r: (
            -int(r["Critical"]),
            -float(r["Max CVSS"]),
            -int(r["High"]),
            -int(r["All CVE"]),
            -int(r["Unique CVE"]),
            -int(r["Config"]),
            -int(r["Over3"]),
            str(r["Podmiot"]).lower(),
        )
    )

    top_entities = entity_rows[:TOP_N]

    # TOP5 most serious CVE NAMES:
    # ranking is CVSS-first. One entity is counted once in "Liczba podmiotów",
    # but we also retain total finding count as a tie-breaker.
    cve_rows = []

    if not cur_findings.empty:
        for cve, g_findings in cur_findings.groupby("CVE", dropna=False):
            cve_id = normalize_cve_id(cve)
            if not cve_id:
                continue

            g_entities = cur_entity_cve[
                cur_entity_cve["CVE"].astype(str).map(normalize_cve_id)
                == cve_id
            ].copy()

            entities_now = {
                x
                for x in g_entities["PresentationEntity"].dropna().astype(str)
                if x
            }

            prev_g_entities = prev_entity_cve[
                prev_entity_cve["CVE"].astype(str).map(normalize_cve_id)
                == cve_id
            ].copy()

            entities_prev = {
                x
                for x in prev_g_entities["PresentationEntity"].dropna().astype(str)
                if x
            }

            scores = pd.to_numeric(
                g_findings["CVSS"],
                errors="coerce",
            ).dropna()

            max_score = (
                float(scores.max())
                if not scores.empty
                else None
            )

            occurrence_severities = [
                effective_severity_and_cvss(r)[0]
                for _, r in g_findings.iterrows()
            ]
            group_has_critical = any(sev == "critical" for sev in occurrence_severities)

            if group_has_critical:
                strongest_sev = "critical"
            elif max_score is not None:
                if max_score >= 7.0:
                    strongest_sev = "high"
                elif max_score >= 4.0:
                    strongest_sev = "medium"
                elif max_score > 0.0:
                    strongest_sev = "low"
                else:
                    strongest_sev = "unknown"
            else:
                strongest_sev = max(
                    occurrence_severities or ["unknown"],
                    key=severity_rank,
                )

            critical = group_has_critical

            raw_g = cur_prepared[
                (cur_prepared["PresentationClass"] == class_code)
                & (
                    cur_prepared["CVE"]
                    .astype(str)
                    .map(normalize_cve_id)
                    == cve_id
                )
            ]

            cve_rows.append({
                "CVE": cve_id,
                "Produkt": _product_hint_for_cve(
                    raw_g if not raw_g.empty else g_findings
                ),
                "Entities": len(entities_now),
                "Entities Display": _format_count_delta(
                    len(entities_now),
                    len(entities_prev),
                ),
                "Findings": int(len(g_findings)),
                "Severity": strongest_sev,
                "Severity Rank": severity_rank(strongest_sev),
                "Critical": critical,
                "CVSS": (
                    max_score
                    if max_score is not None
                    else ""
                ),
                "Has CVSS": (
                    1 if max_score is not None else 0
                ),
                "CVSS Sort": (
                    max_score
                    if max_score is not None
                    else -1.0
                ),
            })

    # CVSS ALWAYS has priority for "Najpoważniejsze podatności".
    cve_rows.sort(
        key=lambda r: (
            -int(r["Has CVSS"]),
            -float(r["CVSS Sort"]),
            -int(r["Findings"]),
            -int(r["Entities"]),
            str(r["CVE"]),
        )
    )

    return top_entities, cve_rows[:TOP_N]


def discover_all_snapshots(
    root_folder: str,
    current_path: Optional[str] = None,
) -> List[str]:
    """Return every valid snapshot, including multiple scans per month."""
    return discover_snapshot_workbooks(root_folder, current_path, None)


def latest_previous_scan(
    root_folder: str,
    current_path: str,
) -> Optional[str]:
    """Return chronologically newest valid snapshot older than current."""
    current_abs = os.path.abspath(current_path)
    cur_ts = parse_workbook_timestamp(current_path)
    candidates: List[Tuple[datetime, str]] = []

    for p in discover_all_snapshots(root_folder, current_path):
        if os.path.abspath(p) == current_abs:
            continue
        ts = parse_workbook_timestamp(p)
        if ts < cur_ts:
            candidates.append((ts, p))

    candidates.sort(key=lambda x: x[0])
    return candidates[-1][1] if candidates else None


def build_critical_trend(
    root_folder: str,
    current_path: str,
    class_code: str,
    class_map: Optional[Dict[str, str]] = None,
    current_detail: Optional[pd.DataFrame] = None,
) -> List[Tuple[datetime, int]]:
    """
    Build the critical-occurrence trend.

    Historical points:
        reconstructed from each historical All_data_detailed sheet.

    CURRENT point:
        calculated directly from the in-memory current scan dataframe when
        current_detail is supplied. This avoids any possibility that the chart
        reloads a stale/reduced worksheet representation.

    Critical occurrence:
        every preserved source CVE occurrence whose primary finding has CVSS 9.0..10.0.

    Classification invariant:
        every occurrence belongs to exactly one of PK / PI / PP.
    """
    points: List[Tuple[datetime, int]] = []
    current_abs = os.path.abspath(current_path)

    snapshots = discover_all_snapshots(root_folder, current_path)

    for path in snapshots:
        try:
            ts = parse_workbook_timestamp(path)
        except Exception:
            ts = datetime.fromtimestamp(os.path.getmtime(path))

        if (
            current_detail is not None
            and os.path.abspath(path) == current_abs
        ):
            raw_df = current_detail.copy()
        else:
            raw_df = _safe_read_sheet(path, "All_data_detailed")

        prepared = _prepare_cve_frame(raw_df, class_map)
        findings = _logical_cve_finding_frame(prepared)

        if findings.empty:
            count = 0
        else:
            class_findings = findings[
                findings["PresentationClass"] == class_code
            ].copy()

            count = (
                int(class_findings.apply(is_critical_record, axis=1).sum())
                if not class_findings.empty
                else 0
            )

        points.append((ts, count))

    # Guarantee the current run is present even if snapshot discovery failed
    # for any filesystem reason.
    if current_detail is not None:
        try:
            current_ts = parse_workbook_timestamp(current_path)
        except Exception:
            current_ts = datetime.fromtimestamp(os.path.getmtime(current_path))

        if not any(os.path.abspath(p) == current_abs for p in snapshots):
            prepared = _prepare_cve_frame(current_detail, class_map)
            findings = _logical_cve_finding_frame(prepared)
            class_findings = (
                findings[findings["PresentationClass"] == class_code].copy()
                if not findings.empty
                else pd.DataFrame()
            )
            current_count = (
                int(class_findings.apply(is_critical_record, axis=1).sum())
                if not class_findings.empty
                else 0
            )
            points.append((current_ts, current_count))

    points.sort(key=lambda x: x[0])
    return points


def export_presentation_csvs(excel_root: str, stamp: str, all_detail: pd.DataFrame,
                             all_cfg_detail: pd.DataFrame, history_df: pd.DataFrame,
                             class_map: Optional[Dict[str, str]] = None) -> List[str]:
    outputs = []
    cves = _prepare_cve_frame(all_detail, class_map)
    cfg = _prepare_cfg_frame(all_cfg_detail, class_map)
    hist = history_df.copy() if history_df is not None else pd.DataFrame()
    for code in PRESENTATION_CLASSES:
        rows = []
        c = cves[cves["PresentationClass"] == code]
        for _, r in c.iterrows():
            hmatch = hist[(hist.get("Type", pd.Series(dtype=str)).astype(str) == "CVE") &
                          (hist.get("Domain", pd.Series(dtype=str)).astype(str).map(lambda d: presentation_entity_for_domain(d, class_map)) == (r.get("PresentationEntity", "") or presentation_entity_for_domain(r.get("Domain", ""), class_map))) &
                          (hist.get("Vulnerability", pd.Series(dtype=str)).astype(str).str.upper() == str(r.get("CVE", "")).upper())] if not hist.empty else pd.DataFrame()
            hr = hmatch.iloc[0] if not hmatch.empty else {}
            entity = r.get("PresentationEntity", "") or presentation_entity_for_domain(r.get("Domain", ""), class_map)
            rows.append({
                "Typ": "CVE", "Klasa": code, "Podmiot": entity,
                "Domena źródłowa": r.get("Domain", ""),
                "Podatnosc": r.get("CVE", ""), "Severity": r.get("Severity", ""),
                "CVSS": r.get("CVSS", ""), "First Seen": hr.get("First Seen", "") if hasattr(hr, "get") else "",
                "Last Seen": hr.get("Last Seen", "") if hasattr(hr, "get") else "",
                "Consecutive Months": hr.get("Consecutive Months", "") if hasattr(hr, "get") else "",
                "Status": hr.get("Current Status", "") if hasattr(hr, "get") else "",
                "Szczegoly": r.get("Description", "")
            })
        g = cfg[cfg["PresentationClass"] == code]
        for _, r in g.iterrows():
            hmatch = hist[(hist.get("Type", pd.Series(dtype=str)).astype(str) == "CONFIG") &
                          (hist.get("Domain", pd.Series(dtype=str)).astype(str).map(lambda d: presentation_entity_for_domain(d, class_map)) == (r.get("PresentationEntity", "") or presentation_entity_for_domain(r.get("Domain", ""), class_map))) &
                          (hist.get("Vulnerability", pd.Series(dtype=str)).astype(str) == str(r.get("Description", "")))] if not hist.empty else pd.DataFrame()
            hr = hmatch.iloc[0] if not hmatch.empty else {}
            entity = r.get("PresentationEntity", "") or presentation_entity_for_domain(r.get("Domain", ""), class_map)
            rows.append({
                "Typ": "CONFIG", "Klasa": code, "Podmiot": entity,
                "Domena źródłowa": r.get("Domain", ""),
                "Podatnosc": r.get("Description", ""), "Severity": "", "CVSS": "",
                "First Seen": hr.get("First Seen", "") if hasattr(hr, "get") else "",
                "Last Seen": hr.get("Last Seen", "") if hasattr(hr, "get") else "",
                "Consecutive Months": hr.get("Consecutive Months", "") if hasattr(hr, "get") else "",
                "Status": hr.get("Current Status", "") if hasattr(hr, "get") else "",
                "Szczegoly": r.get("Details", "")
            })
        df = pd.DataFrame(rows)
        path = os.path.join(excel_root, f"prezentacja_szczegoly_{code}_{stamp}.csv")
        df.to_csv(path, index=False, encoding="utf-8-sig")
        outputs.append(path)
    return outputs


def audit_presentation_metrics(
    all_detail: pd.DataFrame,
    all_cfg_detail: pd.DataFrame,
    class_map: Optional[Dict[str, str]] = None,
    log_fp=None,
) -> None:
    """
    Audit PK/PI/PP critical counts.

    For every class logs:
      raw_CVE_rows
      finding_level_rows            -> CVE+Domain+IP
      scored_rows
      critical_findings             -> explicit critical OR CVSS >= 9.0
      unique_critical_CVE
      critical_entities
      textual_critical_without_CVSS -> intentionally NOT counted
      duplicate_finding_identities  -> must be 0 after logical dedupe
    """
    prepared = _prepare_cve_frame(all_detail, class_map)
    findings = _logical_cve_finding_frame(prepared)

    all_critical = (
        findings[findings.apply(is_critical_record, axis=1)].copy()
        if not findings.empty
        else pd.DataFrame()
    )
    total_critical = int(len(all_critical))

    class_total = 0
    for _cls in PRESENTATION_CLASSES:
        if not all_critical.empty:
            class_total += int(
                (all_critical["PresentationClass"] == _cls).sum()
            )

    log_line(
        f"[*] CRITICAL INVARIANT: total={total_critical}, "
        f"PK+PI+PP={class_total}, difference={total_critical - class_total}",
        log_fp,
    )

    if total_critical != class_total:
        raise RuntimeError(
            "Critical findings disappeared during PK/PI/PP classification: "
            f"total={total_critical}, PK+PI+PP={class_total}"
        )

    for code_ in PRESENTATION_CLASSES:
        raw_c = prepared[
            prepared["PresentationClass"] == code_
        ].copy()

        f = findings[
            findings["PresentationClass"] == code_
        ].copy()

        if f.empty:
            scored_rows = 0
            critical_findings = 0
            unique_critical_cves = 0
            critical_entities = 0
            repeated_same_asset_cve = 0
        else:
            scores = f["CVSS"].map(_valid_cvss_number)
            scored_rows = int(scores.notna().sum())

            crit_mask = f.apply(
                is_critical_record,
                axis=1,
            )
            crit = f[crit_mask].copy()

            critical_findings = int(len(crit))
            unique_critical_cves = int(crit["CVE"].nunique())
            critical_entities = int(
                crit["PresentationEntity"].nunique()
            )

            # Repeated CVE+Domain+IP combinations are legitimate source
            # occurrences and must NOT be removed from critical counts.
            repeated_same_asset_cve = int(
                f.duplicated(
                    subset=[
                        "PresentationEntity",
                        "CVE",
                        "Domain",
                        "IP",
                    ],
                    keep=False,
                ).sum()
            )

        # Diagnostic only: original textual critical but no numeric CVSS.
        textual_critical_without_cvss = 0
        if not all_detail.empty:
            tmp = all_detail.copy()
            if "Domain" not in tmp.columns:
                tmp["Domain"] = ""
            if "Group" not in tmp.columns:
                tmp["Group"] = ""
            if "Severity" not in tmp.columns:
                tmp["Severity"] = ""
            if "CVSS" not in tmp.columns:
                tmp["CVSS"] = ""
            if "Raw Finding" not in tmp.columns:
                tmp["Raw Finding"] = ""
            if "Description" not in tmp.columns:
                tmp["Description"] = ""

            tmp["__class"] = tmp.apply(
                lambda r: presentation_class_for_domain(
                    r.get("Domain", ""),
                    r.get("Group", ""),
                    class_map,
                ),
                axis=1,
            )
            tmp = tmp[tmp["__class"] == code_].copy()

            textual_critical_without_cvss = int(
                tmp.apply(
                    lambda r: (
                        normalize_severity(r.get("Severity", "")) == "critical"
                        and effective_severity_and_cvss(r)[1] is None
                    ),
                    axis=1,
                ).sum()
            ) if not tmp.empty else 0

        log_line(
            f"[*] PRESENTATION AUDIT {code_}: "
            f"raw_CVE_rows={len(raw_c)}, "
            f"finding_level_rows={len(f)}, "
            f"scored_rows={scored_rows}, "
            f"critical_findings={critical_findings}, "
            f"unique_critical_CVE={unique_critical_cves}, "
            f"critical_entities={critical_entities}, "
            f"textual_critical_without_CVSS="
            f"{textual_critical_without_cvss}, "
            f"repeated_same_CVE_domain_IP_rows="
            f"{repeated_same_asset_cve}",
            log_fp,
        )



def add_presentation_dashboards(workbook_path: str, root_folder: str,
                                all_detail: pd.DataFrame, all_cfg_detail: pd.DataFrame,
                                history_df: pd.DataFrame, prev_path: Optional[str],
                                class_map: Optional[Dict[str, str]] = None) -> None:
    wb = load_workbook(workbook_path)
    for name in ["TOP5_PK", "TOP5_PI", "TOP5_PP", "_Dashboard_Data", "Critical_Audit"]:
        if name in wb.sheetnames:
            del wb[name]
    data_ws = wb.create_sheet("_Dashboard_Data")
    data_ws.sheet_state = "hidden"
    data_row = 1

    # Visible audit sheet: every CURRENT critical CVE occurrence.
    audit_ws = wb.create_sheet("Critical_Audit")

    prepared_current = _prepare_cve_frame(all_detail, class_map)
    current_occurrences = _logical_cve_finding_frame(prepared_current)

    if not current_occurrences.empty:
        current_critical = current_occurrences[
            current_occurrences.apply(is_critical_record, axis=1)
        ].copy()
    else:
        current_critical = pd.DataFrame()

    audit_headers = [
        "Folder",
        "Klasa",
        "Podmiot",
        "Domena",
        "IP",
        "CVE",
        "CVSS",
        "Severity z CVSS",
        "Source File",
        "Occurrence ID",
    ]

    for c_idx, header in enumerate(audit_headers, 1):
        audit_ws.cell(1, c_idx, header)

    audit_ws.freeze_panes = "A2"
    audit_ws.sheet_view.showGridLines = False

    if not current_critical.empty:
        for r_idx, (_, r) in enumerate(current_critical.iterrows(), 2):
            values = [
                r.get("Folder", ""),
                r.get("PresentationClass", ""),
                r.get("PresentationEntity", ""),
                r.get("Domain", ""),
                r.get("IP", ""),
                r.get("CVE", ""),
                r.get("CVSS", ""),
                r.get("Severity", ""),
                r.get("Source File", ""),
                r.get("Occurrence ID", ""),
            ]
            for c_idx, value in enumerate(values, 1):
                audit_ws.cell(r_idx, c_idx, value)

    # Summary is deliberately independent of the TOP5 ranking.
    summary_col = 12
    audit_ws.cell(1, summary_col, "Kontrola liczby critical")
    audit_ws.cell(2, summary_col, "Wszystkie critical")
    audit_ws.cell(
        2,
        summary_col + 1,
        int(len(current_critical)) if not current_critical.empty else 0,
    )

    class_counts_current = {}
    for cls in PRESENTATION_CLASSES:
        cls_count = (
            int((current_critical["PresentationClass"] == cls).sum())
            if not current_critical.empty
            else 0
        )
        class_counts_current[cls] = cls_count
        row_num = 3 + PRESENTATION_CLASSES.index(cls)
        audit_ws.cell(row_num, summary_col, cls)
        audit_ws.cell(row_num, summary_col + 1, cls_count)

    classified_sum = sum(class_counts_current.values())
    total_current_critical = (
        int(len(current_critical))
        if not current_critical.empty
        else 0
    )
    audit_ws.cell(6, summary_col, "PK+PI+PP")
    audit_ws.cell(6, summary_col + 1, classified_sum)
    audit_ws.cell(7, summary_col, "Różnica")
    audit_ws.cell(
        7,
        summary_col + 1,
        total_current_critical - classified_sum,
    )

    # Hard invariant: no critical finding may disappear from all classes.
    if classified_sum != total_current_critical:
        raise RuntimeError(
            "Critical classification invariant failed: "
            f"total={total_current_critical}, "
            f"PK+PI+PP={classified_sum}"
        )

    thin = Side(style="thin", color=DASHBOARD_BORDER_COLOR)
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    header_fill = PatternFill("solid", fgColor=DASHBOARD_HEADER_FILL)
    sub_fill = PatternFill("solid", fgColor=DASHBOARD_SUBHEADER_FILL)
    body_fill = PatternFill("solid", fgColor=DASHBOARD_BODY_FILL)

    for code in PRESENTATION_CLASSES:
        ws = wb.create_sheet(f"TOP5_{code}")
        ws.sheet_view.showGridLines = False
        ws.freeze_panes = "A2"
        ws.column_dimensions["A"].width = 27
        ws.column_dimensions["B"].width = 20
        ws.column_dimensions["C"].width = 23
        ws.column_dimensions["D"].width = 22
        ws.column_dimensions["E"].width = 36
        ws.column_dimensions["F"].width = 3
        ws.column_dimensions["G"].width = 20
        ws.column_dimensions["H"].width = 15
        ws.column_dimensions["I"].width = 10
        ws.column_dimensions["J"].width = 28
        ws.column_dimensions["K"].width = 22

        top_entities, top_cves = build_presentation_data(all_detail, all_cfg_detail, history_df, prev_path, code, class_map)

        headers = ["Podmiot", "Liczba podatności krytycznych", "Liczba podatności konfiguracyjnych", "Liczba podatności powyżej 3 miesięcy", "Uwagi"]
        for col, value in enumerate(headers, 1):
            cell = ws.cell(1, col, value)
            cell.fill = header_fill; cell.font = Font(color="FFFFFF", bold=True)
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True); cell.border = border
        ws.row_dimensions[1].height = 55

        for r_idx in range(2, 2 + TOP_N):
            item = top_entities[r_idx - 2] if r_idx - 2 < len(top_entities) else None
            vals = [
                item["Podmiot"] if item else "",
                item["Critical Display"] if item else "",
                item["Config Display"] if item else "",
                item["Over3"] if item else "",
                item["Uwagi"] if item else "",
            ]
            for c_idx, val in enumerate(vals, 1):
                cell = ws.cell(r_idx, c_idx, val); cell.fill = body_fill; cell.border = border
                cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            ws.row_dimensions[r_idx].height = 58

        ws.merge_cells("G1:K1")
        c = ws["G1"]; c.value = "Najpoważniejsze podatności"; c.fill = header_fill
        c.font = Font(color="FFFFFF", bold=True); c.alignment = Alignment(horizontal="center", vertical="center"); c.border = border

        top_headers = ["CVE", "Severity", "CVSS", "Produkt / usługa", "Liczba podmiotów"]
        for col, value in zip(range(7, 12), top_headers):
            cell = ws.cell(2, col, value)
            cell.fill = sub_fill
            cell.font = Font(bold=True)
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border = border

        for r_idx in range(3, 3 + TOP_N):
            item = top_cves[r_idx - 3] if r_idx - 3 < len(top_cves) else None
            vals = [
                item["CVE"] if item else "",
                item["Severity"] if item else "",
                item["CVSS"] if item else "",
                item["Produkt"] if item else "",
                item["Entities Display"] if item else "",
            ]
            for c_idx, val in zip(range(7, 12), vals):
                cell = ws.cell(r_idx, c_idx, val)
                cell.fill = body_fill
                cell.border = border
                cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

        # Trend data + line chart.
        trend = build_critical_trend(
            root_folder,
            workbook_path,
            code,
            class_map,
            current_detail=all_detail,
        )
        start_row = data_row
        data_ws.cell(start_row, 1, f"Data_{code}")
        data_ws.cell(start_row, 2, f"Critical_{code}")
        for i, (dt, value) in enumerate(trend, start_row + 1):
            data_ws.cell(i, 1, dt)
            data_ws.cell(i, 1).number_format = "dd.mm.yyyy"
            data_ws.cell(i, 2, value)
        if trend:
            chart = LineChart()
            chart.title = "Liczba podatności krytycznych"
            chart.y_axis.title = "Liczba"
            chart.x_axis.title = "Data skanu"
            chart.height = 8.0; chart.width = 16.5
            chart.legend = None
            values = Reference(data_ws, min_col=2, min_row=start_row, max_row=start_row + len(trend))
            cats = Reference(data_ws, min_col=1, min_row=start_row + 1, max_row=start_row + len(trend))
            chart.add_data(values, titles_from_data=True)
            chart.set_categories(cats)
            chart.style = 2
            ws.add_chart(chart, "G10")
        else:
            ws["G10"] = "Brak historycznych danych o podatnościach krytycznych."
        data_row += max(len(trend) + 3, 5)

        ws["A8"] = f"TOP5 {code} – Critical = liczba rzeczywistych wpisów CVE oznaczonych jako krytyczne/critical LUB z CVSS >= 9.0; ranking: critical → najwyższy CVSS → high → wszystkie findingi CVE → konfiguracyjne → >3 miesiące"
        ws["A8"].font = Font(italic=True, color="666666")
        ws.merge_cells("A8:E8")
        ws["A9"] = "W nawiasie pokazano zmianę względem bezpośrednio poprzedniego skanu."
        ws["A9"].font = Font(italic=True, color="666666")
        ws.merge_cells("A9:E9")

    wb.save(workbook_path)


# ---------------------------------------------------------------------------
# Workbook writing
# ---------------------------------------------------------------------------

def write_per_folder(path: str, detail_df, agg_df, config_df, config_detail_df, all_findings_df) -> None:
    with pd.ExcelWriter(path, engine="openpyxl") as w:
        detail_df.to_excel(w, sheet_name="CVE_stats_detailed", index=False)
        agg_df.to_excel(w, sheet_name="CVE_stats", index=False)
        config_df.to_excel(w, sheet_name="Config_Issues", index=False)
        config_detail_df.to_excel(w, sheet_name="Config_Detailed", index=False)
        all_findings_df.to_excel(w, sheet_name="All_Findings", index=False)


def write_combined(path: str, results, all_detail, all_stats, all_cfg, all_cfg_detail, all_findings, history_df) -> None:
    with pd.ExcelWriter(path, engine="openpyxl") as w:
        for folder, detail_df, agg_df, config_df, config_detail_df, all_findings_df in results:
            detail_df.to_excel(w, sheet_name=safe_sheet_name(folder, "CVE_stats_detailed"), index=False)
            agg_df.to_excel(w, sheet_name=safe_sheet_name(folder, "CVE_stats"), index=False)
            config_df.to_excel(w, sheet_name=safe_sheet_name(folder, "Config_Issues"), index=False)
            config_detail_df.to_excel(w, sheet_name=safe_sheet_name(folder, "Config_Detailed"), index=False)
        all_detail.to_excel(w, sheet_name="All_data_detailed", index=False)
        all_stats.to_excel(w, sheet_name="All_data", index=False)
        all_cfg.to_excel(w, sheet_name="Config_All_By_Folder", index=False)
        all_cfg_detail.to_excel(w, sheet_name="All_Config_Detailed", index=False)
        all_findings.to_excel(w, sheet_name="All_Findings_Detailed", index=False)
        history_df.to_excel(w, sheet_name="History", index=False)


def write_diff(path_txt: str, path_xlsx: str, lines: List[str], cve_df: pd.DataFrame, cfg_df: pd.DataFrame, history_df: pd.DataFrame) -> None:
    with open(path_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    with pd.ExcelWriter(path_xlsx, engine="openpyxl") as w:
        cve_df.to_excel(w, sheet_name="CVE_Folder_Changes", index=False)
        cfg_df.to_excel(w, sheet_name="Config_Changes", index=False)
        history_df.to_excel(w, sheet_name="History", index=False)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Expected invocation:

        python3 odprawa_miesieczna.py \
            html_reports \
            ~/Raportowanie/Raportowanie_Ignacy/domeny_przypisane.xlsx \
            /mnt/hgfs/iggy_vbox/skany/Podmioty.xlsx

    Arguments:
      1. html_reports
         Folder containing HTML/PDF reports. May be relative or absolute.

      2. domeny_przypisane.xlsx
         Domain/group mapping workbook. Supports ~, relative and absolute paths.

      3. Podmioty.xlsx
         PK/PI/PP presentation mapping workbook. Supports ~, relative and absolute paths.
    """
    if len(sys.argv) != 4:
        script_name = os.path.basename(sys.argv[0]) or "odprawa_miesieczna.py"
        print(
            f"Uzycie: python3 {script_name} "
            "<html_reports> <domeny_przypisane.xlsx> <Podmioty.xlsx>"
        )
        print("")
        print("Przyklad:")
        print(
            f"  python3 {script_name} "
            "html_reports "
            "~/Raportowanie/Raportowanie_Ignacy/domeny_przypisane.xlsx "
            "/mnt/hgfs/iggy_vbox/skany/Podmioty.xlsx"
        )
        sys.exit(1)

    # Expand '~' ourselves as well. Normally the shell expands an unquoted ~,
    # but explicit handling makes the script robust also for quoted arguments
    # and programmatic invocation.
    root_folder = os.path.abspath(os.path.expanduser(sys.argv[1]))
    mapping_arg = os.path.abspath(os.path.expanduser(sys.argv[2]))
    presentation_mapping_arg = os.path.abspath(os.path.expanduser(sys.argv[3]))

    if not os.path.isdir(root_folder):
        sys.exit(f"[!] Folder raportow nie istnieje: {root_folder}")

    if not os.path.isfile(mapping_arg):
        sys.exit(f"[!] Plik mapowania domen nie istnieje: {mapping_arg}")

    if not mapping_arg.lower().endswith(".xlsx"):
        sys.exit(f"[!] Plik mapowania domen musi byc XLSX: {mapping_arg}")

    if not os.path.isfile(presentation_mapping_arg):
        sys.exit(f"[!] Plik Podmioty.xlsx nie istnieje: {presentation_mapping_arg}")

    if not presentation_mapping_arg.lower().endswith(".xlsx"):
        sys.exit(f"[!] Plik mapowania PK/PI/PP musi byc XLSX: {presentation_mapping_arg}")

    run_dt = datetime.now().replace(microsecond=0)
    stamp = ts_suffix(run_dt)
    excel_root = os.path.join(root_folder, "Excel")
    os.makedirs(excel_root, exist_ok=True)
    log_path = os.path.join(excel_root, f"log_{stamp}.txt")

    with open(log_path, "w", encoding="utf-8") as log_fp:
        log_line(f"[*] Root: {root_folder}", log_fp)
        log_line(f"[*] Run timestamp: {iso_ts(run_dt)}", log_fp)

        mapping_file = resolve_group_mapping_path(root_folder, mapping_arg, log_fp)
        group_map = load_group_map(mapping_file, log_fp)

        presentation_mapping_file = resolve_presentation_mapping_path(
            root_folder,
            presentation_mapping_arg,
            log_fp,
        )
        if presentation_mapping_file:
            log_line(
                f"[*] Dedicated PK/PI/PP mapping workbook: {presentation_mapping_file}",
                log_fp,
            )

        presentation_class_map = load_presentation_class_map(
            presentation_mapping_file,
            log_fp,
        )
        if presentation_class_map:
            log_line(
                "[*] Dashboard entity aggregation enabled: every subdomain is "
                "assigned to the matching main domain from the PK/PI/PP workbook.",
                log_fp,
            )

        html_source_folders = discover_html_source_folders(root_folder)
        log_line(
            f"[*] HTML source folders discovered: {len(html_source_folders)}",
            log_fp,
        )
        for source_folder in html_source_folders:
            log_line(f"    - {source_folder}", log_fp)

        # Historical XLSX snapshots can be directly in html_reports or in any
        # nested folder. Log them before generating the current snapshot.
        discover_snapshot_workbooks(root_folder, None, log_fp)

        results = []
        used_labels: Set[str] = set()
        for source_folder in html_source_folders:
            label = unique_folder_label(
                source_folder, root_folder, used_labels
            )
            res = process_folder(
                source_folder,
                log_fp,
                group_map,
                folder_label=label,
            )
            if res is not None:
                results.append(res)

        if not results:
            log_line("[!] No findings extracted from any folder.", log_fp)
            return

        for folder, detail_df, agg_df, config_df, config_detail_df, all_findings_df in results:
            per = os.path.join(excel_root, f"findings_{folder}_{stamp}.xlsx")
            write_per_folder(per, detail_df, agg_df, config_df, config_detail_df, all_findings_df)
            log_line(f"[+] Wrote per-folder workbook: {per}", log_fp)

        all_detail, all_stats, all_cfg_by_folder, all_cfg_detail, all_findings = build_all_data_frames(results)
        konfig_all = build_konfiguracyjne_all_aggregated(all_cfg_detail, group_map)

        new_basename = f"findings_all_{stamp}.xlsx"
        new_path = os.path.join(root_folder, new_basename)
        # IMPORTANT: ALL historical findings workbooks are used.
        previous_paths = discover_previous_workbooks(
            root_folder,
            new_basename,
            run_dt,
            log_fp,
        )

        # Immediate predecessor for diff/delta calculations.
        prev_path = previous_paths[-1] if previous_paths else None

        cur_state = current_state_from_frames(
            all_detail,
            all_cfg_detail,
        )
        history_df = build_history(
            previous_paths,
            cur_state,
            run_dt,
        )

        log_line(
            f"[*] History built from {len(previous_paths)} historical "
            f"snapshot(s) + current scan.",
            log_fp,
        )

        # Combined workbook includes both legacy-friendly sheets and exhaustive detailed sheets.
        with pd.ExcelWriter(new_path, engine="openpyxl") as w:
            for folder, detail_df, agg_df, config_df, config_detail_df, all_findings_df in results:
                detail_df.to_excel(w, sheet_name=safe_sheet_name(folder, "CVE_stats_detailed"), index=False)
                agg_df.to_excel(w, sheet_name=safe_sheet_name(folder, "CVE_stats"), index=False)
                config_df.to_excel(w, sheet_name=safe_sheet_name(folder, "Config_Issues"), index=False)
                config_detail_df.to_excel(w, sheet_name=safe_sheet_name(folder, "Config_Detailed"), index=False)
            all_detail.to_excel(w, sheet_name="All_data_detailed", index=False)
            all_stats.to_excel(w, sheet_name="All_data", index=False)
            konfig_all.to_excel(w, sheet_name="Konfiguracyjne_all", index=False)
            all_cfg_by_folder.to_excel(w, sheet_name="Config_All_By_Folder", index=False)
            all_cfg_detail.to_excel(w, sheet_name="All_Config_Detailed", index=False)
            all_findings.to_excel(w, sheet_name="All_Findings_Detailed", index=False)
            history_df.to_excel(w, sheet_name="History", index=False)

            # Audit trail: every historical findings workbook that contributed
            # to history/trend calculations, plus the current run.
            timeline_rows = []
            for _p in previous_paths:
                try:
                    _ts = parse_workbook_timestamp(_p)
                except Exception:
                    _ts = datetime.fromtimestamp(os.path.getmtime(_p))
                timeline_rows.append({
                    "Timestamp": _ts,
                    "Workbook": os.path.basename(_p),
                    "Path": _p,
                    "Role": "historical",
                })
            timeline_rows.append({
                "Timestamp": run_dt,
                "Workbook": os.path.basename(new_path),
                "Path": new_path,
                "Role": "current",
            })
            pd.DataFrame(timeline_rows).to_excel(
                w,
                sheet_name="Snapshot_Timeline",
                index=False,
            )

        # Presentation deltas compare against the immediately preceding scan snapshot,
        # while History above is reconstructed from every supplied snapshot.
        prev_scan_path = latest_previous_scan(root_folder, new_path)
        audit_critical_counts_by_folder_and_class(
            all_detail,
            presentation_class_map,
            log_fp,
        )
        audit_presentation_metrics(
            all_detail,
            all_cfg_detail,
            presentation_class_map,
            log_fp,
        )
        add_presentation_dashboards(
            new_path,
            root_folder,
            all_detail,
            all_cfg_detail,
            history_df,
            prev_scan_path,
            presentation_class_map,
        )
        log_line("[+] Added presentation dashboards: TOP5_PK, TOP5_PI, TOP5_PP", log_fp)
        log_line(f"[*] Dashboard comparison snapshot: {prev_scan_path or 'none (first scan)'}", log_fp)

        for csv_path in export_presentation_csvs(excel_root, stamp, all_detail, all_cfg_detail, history_df, presentation_class_map):
            log_line(f"[+] Wrote presentation detail CSV: {csv_path}", log_fp)

        log_line(f"[+] Wrote combined workbook: {new_path}", log_fp)

        prev_state = load_state_from_workbook(prev_path) if prev_path else {}
        lines, cve_diff, cfg_diff = build_diff(prev_state, cur_state, history_df)
        lines.insert(1, f"Previous: {os.path.basename(prev_path) if prev_path else 'none'}")
        lines.insert(2, f"Current:  {os.path.basename(new_path)}")

        diff_txt = os.path.join(root_folder, "diff.txt")
        diff_xlsx = os.path.join(root_folder, "diff.xlsx")
        write_diff(diff_txt, diff_xlsx, lines, cve_diff, cfg_diff, history_df)
        log_line(f"[+] Wrote diff: {diff_txt}", log_fp)
        log_line(f"[+] Wrote diff workbook: {diff_xlsx}", log_fp)

        if not prev_path:
            log_line("[*] No previous findings workbook: current findings are treated as first-seen in the current scan.", log_fp)
        else:
            log_line(f"[*] Compared against: {prev_path}", log_fp)

        log_line("\nAll done.", log_fp)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
merge_html_by_root_domain.py

Łączy raporty HTML subdomen w jeden główny raport HTML dla każdej domeny
podanej w pliku domen.

Przykład:

Folder wejściowy:
    aaa.pl.html
    download.aaa.pl_443.html
    owa.aaa.pl_443.html

    zmt.tarnow.pl.html
    aaa.zmt.tarnow.pl_443.html

    obrum.pl.html
    aaa.obrum.pl_443.html
    bbb.obrum.pl_443.html

domeny.txt:
    aaa.pl
    zmt.tarnow.pl
    obrum.pl

Wynik:
    messages/
        aaa.pl.html
        zmt.tarnow.pl.html
        obrum.pl.html

Zasady:
- lista domen z drugiego argumentu jest autorytatywna;
- aaa.obrum.pl przypisywane jest do obrum.pl;
- aaa.zmt.tarnow.pl przypisywane jest do zmt.tarnow.pl;
- wybierane jest NAJDŁUŻSZE pasujące rozszerzenie domeny;
- port w nazwie pliku (_443, _80, _8443 itd.) jest ignorowany przy mapowaniu;
- treść raportów nie jest filtrowana;
- wszystkie raporty przypisane do domeny trafiają do jednego pliku;
- jeżeli istnieje <root>.html, jego <head> / CSS jest używany jako baza;
- raport głównej domeny trafia jako pierwszy;
- pozostałe raporty są dokładane do jego <body>;
- folder wynikowy zawsze nazywa się "messages".
"""

from __future__ import annotations

import argparse
import html
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from bs4 import BeautifulSoup
except ImportError:
    print(
        "BŁĄD: wymagany jest pakiet beautifulsoup4.\n"
        "Zainstaluj go:\n\n"
        "    pip install beautifulsoup4\n",
        file=sys.stderr,
    )
    sys.exit(1)


# ============================================================
# Konfiguracja
# ============================================================

OUTPUT_FOLDER_NAME = "messages"

# Rozpoznaje np.:
# aaa.pl_443
# aaa.pl_80
# aaa.pl_8443
PORT_SUFFIX_RE = re.compile(r"_(\d{1,5})$", re.IGNORECASE)

# Standardowa domena/FQDN.
FQDN_RE = re.compile(
    r"(?<![A-Za-z0-9.-])"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63})"
    r"(?![A-Za-z0-9.-])",
    re.IGNORECASE,
)

URL_HOST_RE = re.compile(
    r"https?://"
    r"(?:[^@\s/]+@)?"
    r"(?P<host>"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
    r")"
    r"(?::\d{1,5})?",
    re.IGNORECASE,
)


# ============================================================
# Pomocnicze
# ============================================================

def normalize_domain(domain: str) -> str:
    """
    Normalizuje domenę:
        WWW.AAA.PL. -> www.aaa.pl
    """
    domain = (domain or "").strip().lower()
    domain = domain.rstrip(".")

    # Usuń ewentualny port.
    domain = re.sub(r":\d{1,5}$", "", domain)

    return domain


def load_root_domains(path: Path) -> List[str]:
    """
    Wczytuje autorytatywną listę domen głównych.

    Akceptuje:
        aaa.pl
        zmt.tarnow.pl
        obrum.pl

    Puste linie i komentarze # są ignorowane.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Nie istnieje plik domen: {path}")

    roots: List[str] = []
    seen = set()

    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for raw in f:
            line = raw.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            # Pozwala również na:
            # aaa.pl # komentarz
            if "#" in line:
                line = line.split("#", 1)[0].strip()

            root = normalize_domain(line)

            if not root:
                continue

            if root not in seen:
                seen.add(root)
                roots.append(root)

    if not roots:
        raise ValueError("Plik domen nie zawiera żadnych domen.")

    # Najdłuższa domena jako pierwsza.
    #
    # Ważne np. gdy lista zawiera:
    # tarnow.pl
    # zmt.tarnow.pl
    #
    # host aaa.zmt.tarnow.pl powinien zostać przypisany do
    # zmt.tarnow.pl.
    roots.sort(key=lambda x: (-len(x.split(".")), -len(x), x))

    return roots


def filename_to_hostname(path: Path) -> str:
    """
    Próbuje wyciągnąć hostname z nazwy raportu.

    Przykłady:

        download.aaa.pl_443.html
            -> download.aaa.pl

        owa.aaa.pl_443.html
            -> owa.aaa.pl

        aaa.pl.html
            -> aaa.pl

        aaa.zmt.tarnow.pl_8443.html
            -> aaa.zmt.tarnow.pl
    """
    name = path.stem.strip()

    # Usuń końcowy _PORT.
    name = PORT_SUFFIX_RE.sub("", name)

    # Czasami nazwy mogą mieć wariant:
    # https___aaa.pl_443
    name = re.sub(
        r"^(?:https?|wss?)_+",
        "",
        name,
        flags=re.IGNORECASE,
    )

    return normalize_domain(name)


def root_for_hostname(
    hostname: str,
    roots: List[str],
) -> Optional[str]:
    """
    Zwraca najbardziej szczegółową domenę z listy, której hostname
    jest równy lub jest jej subdomeną.

    Przykład:

        roots:
            tarnow.pl
            zmt.tarnow.pl

        hostname:
            aaa.zmt.tarnow.pl

        wynik:
            zmt.tarnow.pl
    """
    host = normalize_domain(hostname)

    if not host:
        return None

    for root in roots:
        if host == root:
            return root

        if host.endswith("." + root):
            return root

    return None


def domains_from_html(path: Path) -> List[str]:
    """
    Fallback: wyciąga domeny występujące w treści HTML.

    Jest używany, gdy nazwa pliku nie pozwala ustalić właściciela raportu.

    Przykład pliku:
        report_001.html

    zawartość:
        https://owa.aaa.pl:443/Autodiscover

    -> wykryte zostanie owa.aaa.pl.
    """
    try:
        raw = path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        return []

    found: List[str] = []
    seen = set()

    # Najpierw URL-e.
    for match in URL_HOST_RE.finditer(raw):
        domain = normalize_domain(match.group("host"))

        if domain and domain not in seen:
            seen.add(domain)
            found.append(domain)

    # Następnie dowolne FQDN-y.
    #
    # To jest fallback, więc URL-e mają pierwszeństwo.
    for match in FQDN_RE.finditer(raw):
        domain = normalize_domain(match.group(1))

        if domain and domain not in seen:
            seen.add(domain)
            found.append(domain)

    return found


def determine_root(
    path: Path,
    roots: List[str],
) -> Tuple[Optional[str], str]:
    """
    Ustala domenę główną dla raportu.

    Kolejność:
    1. nazwa pliku,
    2. treść HTML.

    Zwraca:
        (root_domain, reason)
    """

    # --------------------------------------------------------
    # 1. Nazwa pliku
    # --------------------------------------------------------

    hostname = filename_to_hostname(path)

    root = root_for_hostname(hostname, roots)

    if root:
        return root, f"filename:{hostname}"

    # --------------------------------------------------------
    # 2. Treść raportu
    # --------------------------------------------------------

    domains = domains_from_html(path)

    candidate_roots: List[str] = []

    for domain in domains:
        candidate = root_for_hostname(domain, roots)

        if candidate and candidate not in candidate_roots:
            candidate_roots.append(candidate)

    if len(candidate_roots) == 1:
        return (
            candidate_roots[0],
            f"content:{','.join(domains[:5])}",
        )

    if len(candidate_roots) > 1:
        # To nietypowy przypadek:
        # jeden raport zawiera aktywa kilku podmiotów.
        #
        # Nie zgadujemy.
        return (
            None,
            "ambiguous-content:"
            + ",".join(candidate_roots),
        )

    return None, "no-match"


def read_html(path: Path) -> str:
    return path.read_text(
        encoding="utf-8",
        errors="replace",
    )


def extract_body_inner_html(raw_html: str) -> str:
    """
    Zwraca całą zawartość <body> bez samego tagu <body>.

    Niczego wewnątrz body nie filtrujemy.
    """
    soup = BeautifulSoup(raw_html, "html.parser")

    if soup.body:
        return "".join(
            str(child)
            for child in soup.body.contents
        )

    # Jeżeli dokument nie posiada <body>, zachowujemy całość.
    return raw_html


def extract_head_html(raw_html: str) -> Optional[str]:
    """
    Pobiera <head> z głównego raportu.
    """
    soup = BeautifulSoup(raw_html, "html.parser")

    if soup.head:
        return str(soup.head)

    return None


def build_default_head(root: str) -> str:
    """
    Minimalny HEAD gdy <root>.html nie istnieje.
    """
    safe_root = html.escape(root)

    return f"""<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Raport - {safe_root}</title>

<style>
body {{
    font-family: Arial, Helvetica, sans-serif;
    margin: 40px;
    line-height: 1.5;
}}

.report-source {{
    margin-top: 35px;
}}

.report-source + .report-source {{
    border-top: 1px solid #dddddd;
    padding-top: 30px;
}}
</style>
</head>"""


def wrap_source_fragment(
    source: Path,
    fragment: str,
) -> str:
    """
    Dodaje techniczny wrapper do treści jednego raportu.

    Wrapper nie zmienia wizualnie treści.
    data-source pozwala później zobaczyć skąd pochodzi wpis.
    """

    safe_filename = html.escape(
        source.name,
        quote=True,
    )

    return (
        f'\n<!-- SOURCE FILE: {safe_filename} -->\n'
        f'<div class="merged-report-source" '
        f'data-source="{safe_filename}">\n'
        f'{fragment}\n'
        f'</div>\n'
        f'<!-- END SOURCE FILE: {safe_filename} -->\n'
    )


def source_sort_key(
    path: Path,
    root: str,
) -> Tuple[int, str]:
    """
    Główny root.html zawsze trafia jako pierwszy.

    Następnie pozostałe pliki alfabetycznie.
    """
    exact_main = path.name.lower() == f"{root}.html".lower()

    return (
        0 if exact_main else 1,
        path.name.lower(),
    )


def merge_reports_for_root(
    root: str,
    files: List[Path],
    output_path: Path,
) -> None:
    """
    Tworzy jeden HTML dla root domain.
    """

    files = sorted(
        files,
        key=lambda p: source_sort_key(p, root),
    )

    # --------------------------------------------------------
    # Szukamy głównego <root>.html
    # --------------------------------------------------------

    main_file: Optional[Path] = None

    for path in files:
        if path.name.lower() == f"{root}.html".lower():
            main_file = path
            break

    # --------------------------------------------------------
    # HEAD
    # --------------------------------------------------------

    if main_file:
        main_raw = read_html(main_file)

        head_html = (
            extract_head_html(main_raw)
            or build_default_head(root)
        )
    else:
        head_html = build_default_head(root)

    # --------------------------------------------------------
    # BODY
    # --------------------------------------------------------

    fragments: List[str] = []

    for source in files:
        try:
            raw = read_html(source)
            body = extract_body_inner_html(raw)

        except Exception as exc:
            print(
                f"[!] Błąd podczas czytania "
                f"{source}: {exc}",
                file=sys.stderr,
            )
            continue

        # NICZEGO z body nie filtrujemy.
        #
        # Czyli jeżeli raport zawiera:
        #
        # - NTLM
        # - Active Directory disclosure
        # - Joomla
        # - DMARC
        # - SPF
        # - SSL
        # - phpinfo
        # - WordPress
        # - dowolny nowy finding
        #
        # wszystko zostanie przeniesione.
        fragments.append(
            wrap_source_fragment(
                source,
                body,
            )
        )

    safe_root = html.escape(root)

    output = f"""<!DOCTYPE html>
<html lang="pl">
{head_html}
<body>

<!--
MERGED REPORT
Root domain: {safe_root}
Files merged: {len(files)}
-->

{''.join(fragments)}

</body>
</html>
"""

    output_path.write_text(
        output,
        encoding="utf-8",
    )


def collect_html_files(
    folder: Path,
    recursive: bool,
) -> List[Path]:
    """
    Pobiera pliki HTML.

    Folder messages jest pomijany, aby wynik poprzedniego uruchomienia
    nie został ponownie dołączony.
    """

    output_dir = (
        folder / OUTPUT_FOLDER_NAME
    ).resolve()

    if recursive:
        candidates = folder.rglob("*")
    else:
        candidates = folder.iterdir()

    files: List[Path] = []

    for path in candidates:
        if not path.is_file():
            continue

        if path.suffix.lower() not in (
            ".html",
            ".htm",
        ):
            continue

        try:
            resolved = path.resolve()

            if output_dir in resolved.parents:
                continue

        except Exception:
            pass

        files.append(path)

    return sorted(
        files,
        key=lambda p: str(p).lower(),
    )


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Łączy raporty HTML subdomen w jeden raport "
            "dla domeny głównej."
        )
    )

    parser.add_argument(
        "html_folder",
        type=Path,
        help=(
            "Folder zawierający raporty HTML, "
            "np. ./html_reports"
        ),
    )

    parser.add_argument(
        "domains_file",
        type=Path,
        help=(
            "Plik TXT zawierający główne domeny, "
            "po jednej w linii."
        ),
    )

    parser.add_argument(
        "--recursive",
        action="store_true",
        help=(
            "Szukaj plików HTML również "
            "w podfolderach."
        ),
    )

    parser.add_argument(
        "--clean",
        action="store_true",
        help=(
            "Usuń istniejący folder messages "
            "przed generowaniem."
        ),
    )

    args = parser.parse_args()

    html_folder = (
        args.html_folder
        .expanduser()
        .resolve()
    )

    domains_file = (
        args.domains_file
        .expanduser()
        .resolve()
    )

    # --------------------------------------------------------
    # Walidacja
    # --------------------------------------------------------

    if not html_folder.is_dir():
        sys.exit(
            f"BŁĄD: folder nie istnieje: "
            f"{html_folder}"
        )

    if not domains_file.is_file():
        sys.exit(
            f"BŁĄD: plik domen nie istnieje: "
            f"{domains_file}"
        )

    # --------------------------------------------------------
    # Domeny główne
    # --------------------------------------------------------

    try:
        roots = load_root_domains(
            domains_file
        )
    except Exception as exc:
        sys.exit(
            f"BŁĄD podczas wczytywania domen: "
            f"{exc}"
        )

    print(
        f"[*] Wczytano domen głównych: "
        f"{len(roots)}"
    )

    # --------------------------------------------------------
    # HTML
    # --------------------------------------------------------

    html_files = collect_html_files(
        html_folder,
        recursive=args.recursive,
    )

    print(
        f"[*] Znaleziono plików HTML: "
        f"{len(html_files)}"
    )

    if not html_files:
        sys.exit(
            "BŁĄD: nie znaleziono plików HTML."
        )

    # --------------------------------------------------------
    # Grupowanie
    # --------------------------------------------------------

    grouped: Dict[str, List[Path]] = defaultdict(list)

    unmapped: List[
        Tuple[Path, str]
    ] = []

    for path in html_files:

        root, reason = determine_root(
            path,
            roots,
        )

        if root:
            grouped[root].append(path)

            print(
                f"[+] {path.name}"
                f"\n    -> {root}"
                f"\n    -> {reason}"
            )

        else:
            unmapped.append(
                (path, reason)
            )

            print(
                f"[?] NIEPRZYPISANY: "
                f"{path.name}"
                f"\n    -> {reason}"
            )

    # --------------------------------------------------------
    # Folder messages
    # --------------------------------------------------------

    output_folder = (
        html_folder
        / OUTPUT_FOLDER_NAME
    )

    if args.clean and output_folder.exists():
        print(
            f"[*] Usuwam poprzedni folder: "
            f"{output_folder}"
        )

        shutil.rmtree(
            output_folder
        )

    output_folder.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # Generowanie
    # --------------------------------------------------------

    generated = 0

    for root in roots:

        files = grouped.get(
            root,
            [],
        )

        if not files:
            print(
                f"[-] Brak raportów dla: "
                f"{root}"
            )
            continue

        output_path = (
            output_folder
            / f"{root}.html"
        )

        merge_reports_for_root(
            root,
            files,
            output_path,
        )

        generated += 1

        print(
            f"\n[OK] {root}"
        )

        print(
            f"     plików wejściowych: "
            f"{len(files)}"
        )

        print(
            f"     wynik: "
            f"{output_path}"
        )

    # --------------------------------------------------------
    # Unmapped log
    # --------------------------------------------------------

    if unmapped:

        unmapped_log = (
            output_folder
            / "_unmapped.txt"
        )

        with unmapped_log.open(
            "w",
            encoding="utf-8",
        ) as f:

            for path, reason in unmapped:
                f.write(
                    f"{path}\t{reason}\n"
                )

        print(
            f"\n[!] Nieprzypisanych plików: "
            f"{len(unmapped)}"
        )

        print(
            f"[!] Lista: "
            f"{unmapped_log}"
        )

    # --------------------------------------------------------
    # Podsumowanie
    # --------------------------------------------------------

    print(
        "\n"
        "====================================\n"
        "             PODSUMOWANIE\n"
        "===================================="
    )

    print(
        f"Pliki HTML wejściowe : "
        f"{len(html_files)}"
    )

    print(
        f"Domeny z raportem    : "
        f"{generated}"
    )

    print(
        f"Nieprzypisane        : "
        f"{len(unmapped)}"
    )

    print(
        f"Folder wynikowy      : "
        f"{output_folder}"
    )

    print(
        "===================================="
    )


if __name__ == "__main__":
    main()

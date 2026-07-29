#!/usr/bin/env python3
"""
Konwerter TXT -> HTML z poprawnym formatowaniem (obsługa CVE + WAS-xxxx jako wpisy listy).
Końcówka raportu jest dokładnie w wymaganej kolejności, bez duplikacji.

FIX (PGP):
- Jeżeli TXT zawiera PGP_NOTICE -> raport powinien mieć dopisek PGP (na czerwono),
  ALE nie wtedy, gdy domena/identyfikator pasuje do regexów z bez_pgp_patterns.
- Jeżeli regex pasuje -> PGP nigdy nie zostanie dopisane (i zostanie usunięte, jeśli już jest).
- Warunek PGP opiera się na oryginalnym pliku .txt (nie na tym, co już jest w HTML),
  więc PGP nie „zniknie” przez wcześniejsze modyfikacje.

Compatibility FIX (nuclei_grouped-derived TXT reports):
- Obsługa obu formatów nagłówka hosta:
    1) "IP: 1.2.3.4 (host.name)"
    2) "host.name (IP: 1.2.3.4)"
  dzięki czemu blok 3-liniowy (IP/Widoczne serwisy/CVEs) jest renderowany spójnie.
- Bardziej tolerancyjne wykrywanie "Zalecamy" (z indentacją).

Użycie:
    python3 script.py folder_z_plikami_txt
"""
import subprocess
import sys
from pathlib import Path
import html
import re

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

# --- Vulnerability tokens (CVE + WordPress WAS-xxxx) ---
VULN_TOKEN_RE = re.compile(r"\b((?:CVE-\d{4}-\d{4,7})|(?:WAS-\d{3,7}))\b", re.I)
VULN_START_RE = re.compile(r"^\s*(?:CVE-\d{4}-\d{4,7}|WAS-\d{3,7})\b", re.I)

# --- Compatibility: host (IP: x.x.x.x) header ---
IP_IN_PARENS_LINE_RE = re.compile(r"^(.+?)\s*\(IP:\s*([\d\.]+)\s*\)$", re.I)
IP_LINE_RE = re.compile(r"^IP:\s*([\d\.]+)\s*\(([^)]+)\)$", re.I)

PGP_NOTICE = "Jednocześnie przypominamy o rekomendowanej formie komunikacji z wykorzystaniem szyfrowania wiadomości PGP."
SPECIFIC_ZALECAMY = (
    "Zalecamy przeprowadzić weryfikację, czy podobne problemy występują "
    "w innych, publicznie udostępnionych przez Państwa systemach"
)

ENDING_LINES = [
    "Jeżeli któreś z podatności nie dotyczą podmiotu, prosimy o informację zwrotną wraz z wyjaśnieniem.",
    "Prosimy pamiętać, że skanowanie jest rozłożone w czasie.",
]

UNWANTED_RECOMMENDATION_BLOCK = """Rekomendacje / uwagi:

- Szanowni Państwo,

w ramach analizy bezpieczeństwa teleinformatycznego w Państwa domenie dgt.pl zidentyfikowaliśmy obiekty, których wersja lub konfiguracja posiada znane podatności."""


def clean_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


def escape_and_highlight_vuln(s: str) -> str:
    escaped = html.escape(s)
    return VULN_TOKEN_RE.sub(lambda m: f"<strong>{m.group(1)}</strong>", escaped)


def parse_artemis_blocks(lines, idx, html_lines):
    """
    Parsuje fragmenty typu Artemis i zamienia je na HTML.
    Wszystkie wpisy w <p>, brak <ul>/<li>.
    """
    start_idx = idx

    def add_header(header_text):
        html_lines.append("<br>")
        html_lines.append(f"<p><strong>{escape_and_highlight_vuln(header_text)}</strong></p>")

    while idx < len(lines):
        line = lines[idx].strip()
        if not line:
            idx += 1
            continue

        if line.startswith("Błąd:"):
            html_lines.append(f"<p>{escape_and_highlight_vuln(line)}</p>")
            html_lines.append("<br>")
            idx += 1
            continue

        if "Polityka DMARC jest ustawiona na 'none'" in line:
            add_header(line)
            idx += 1
            continue

        if re.match(r"^Pod (następującymi|poniższymi) adresami znajdują się", line):
            add_header("Nieaktualne wersje CMS lub wtyczek:")
            idx += 1
            while idx < len(lines) and lines[idx].strip().startswith("https://"):
                html_lines.append(f"<p>{escape_and_highlight_vuln(lines[idx].strip())}</p>")
                idx += 1
            continue

        if line.startswith("Rekord SPF") or line.startswith("Problem z mechanizmem SPF:"):
            add_header(line)
            idx += 1
            while idx < len(lines):
                next_line = lines[idx].strip()
                if not next_line or re.match(r"^\w.*:", next_line):
                    break
                html_lines.append(f"<p>{escape_and_highlight_vuln(next_line)}</p>")
                idx += 1
            continue

        if line.startswith("Pod następującymi adresami znajdują się nieaktualne wersje systemu Joomla"):
            add_header(line)
            idx += 1
            while idx < len(lines):
                next_line = lines[idx].strip()
                if not next_line or re.match(r"^\w.*:", next_line):
                    break
                html_lines.append(f"<p>{escape_and_highlight_vuln(next_line)}</p>")
                idx += 1
            continue

        if line.startswith("Wykryto stronę phpinfo()"):
            add_header(line)
            idx += 1
            while idx < len(lines):
                next_line = lines[idx].strip()
                if not next_line or re.match(r"^\w.*:", next_line):
                    break
                html_lines.append(f"<p>{escape_and_highlight_vuln(next_line)}</p>")
                idx += 1
            continue

        if line.startswith("Wykryto, że następujące nagłówki HTTP"):
            add_header(line)
            idx += 1
            while idx < len(lines):
                next_line = lines[idx].strip()
                if not next_line or re.match(r"^\w.*:", next_line):
                    break
                html_lines.append(f"<p>{escape_and_highlight_vuln(next_line)}</p>")
                idx += 1
            continue

        if line.startswith("Następujące adresy zwracają certyfikaty SSL/TLS wystawione na niepoprawne domeny:"):
            add_header(line)
            idx += 1
            while idx < len(lines):
                next_line = lines[idx].strip()
                if not next_line or re.match(r"^\w.*:", next_line):
                    break
                html_lines.append(f"<p>{escape_and_highlight_vuln(next_line)}</p>")
                idx += 1
            continue

        if line.lstrip("- ").startswith(
            "Następujące domeny nie mają poprawnie skonfigurowanych mechanizmów weryfikacji nadawcy wiadomości e-mail:"
        ):
            clean_header = line.lstrip("- ").strip()
            add_header(clean_header)
            idx += 1
            while idx < len(lines):
                next_line = lines[idx].strip()
                if not next_line or re.match(r"^\w.*:", next_line):
                    break
                html_lines.append(f"<p>{escape_and_highlight_vuln(next_line)}</p>")
                idx += 1
            continue

        if line.startswith("Certyfikaty SSL/TLS pod następującymi adresami nie są podpisane przez zaufane centrum certyfikacji:"):
            add_header(line)
            idx += 1
            while idx < len(lines) and lines[idx].strip().startswith("https://"):
                html_lines.append(f"<p>{escape_and_highlight_vuln(lines[idx].strip())}</p>")
                idx += 1
            continue

        if line.startswith("Wykryto ustawienia stwarzające ryzyko przejęcia domen") or line.startswith(
            "Wykryto ustawienia stwarzające ryzyko przejęcia domeny"
        ):
            add_header(line)
            idx += 1
            while idx < len(lines) and re.match(r"^\s*[\w.-]+\.[\w.-]+: ", lines[idx]):
                html_lines.append(f"<p>{escape_and_highlight_vuln(lines[idx].strip())}</p>")
                idx += 1
            continue

        if re.match(r"^Następujące serwery mają otwarty port bazy danych:", line):
            add_header(line)
            idx += 1
            while idx < len(lines) and lines[idx].strip().startswith("    "):
                html_lines.append(f"<p>{escape_and_highlight_vuln(lines[idx].strip())}</p>")
                idx += 1
            continue

        if line.startswith("Wykryto konfigurację serwerów pozwalającą na listing plików"):
            add_header(
                "Wykryto konfigurację serwerów pozwalającą na listing plików w przynajmniej jednym katalogu. "
                "Problem można zaobserwować np. pod adresami:"
            )
            idx += 1
            while idx < len(lines):
                next_line = lines[idx].strip()
                if not next_line or re.match(r"^\w.*:", next_line):
                    break
                html_lines.append(f"<p>{escape_and_highlight_vuln(next_line)}</p>")
                idx += 1
            continue

        if line.startswith("Nie znaleziono poprawnego rekordu DMARC"):
            add_header(
                "Nie znaleziono poprawnego rekordu DMARC. Rekomendujemy używanie wszystkich trzech mechanizmów: "
                "SPF, DKIM i DMARC, aby zmniejszyć szansę, że sfałszowana wiadomość zostanie zaakceptowana "
                "przez serwer odbiorcy."
            )
            idx += 1
            while idx < len(lines):
                next_line = lines[idx].strip()
                if not next_line or re.match(r"^\w.*:", next_line):
                    break
                html_lines.append(f"<p>{escape_and_highlight_vuln(next_line)}</p>")
                idx += 1
            continue

        if line.startswith("Pod następującymi adresami występuje podatność SQL Injection"):
            add_header(line)
            idx += 1
            while idx < len(lines) and lines[idx].strip().startswith("    "):
                html_lines.append(f"<p>{escape_and_highlight_vuln(lines[idx].strip())}</p>")
                idx += 1
            continue

        if line.startswith("Następujące adresy nie przekierowują z http:// na https://"):
            add_header(line)
            idx += 1
            while idx < len(lines) and lines[idx].strip().startswith("    http://"):
                html_lines.append(f"<p>{escape_and_highlight_vuln(lines[idx].strip())}</p>")
                idx += 1
            continue

        if line.startswith(
            "Poniższe adresy zawierają zasoby takie jak panele logowania, narzędzia analityczne, panele administracyjne itp"
        ):
            add_header(line)
            idx += 1
            while idx < len(lines):
                next_line = lines[idx].strip()
                if not next_line or re.match(r"^\w.*:", next_line):
                    break
                html_lines.append(f"<p>{escape_and_highlight_vuln(next_line)}</p>")
                idx += 1
            continue

        if line.startswith("Nie znaleziono dyrektywy '~all' lub '-all' w rekordzie SPF."):
            add_header(line)
            idx += 1
            while idx < len(lines) and lines[idx].strip().startswith("    "):
                html_lines.append(f"<p>{escape_and_highlight_vuln(lines[idx].strip())}</p>")
                idx += 1
            continue

        if "Jeżeli któreś z podatności nie dotyczą podmiotu" in line:
            html_lines.append("<br>")
            html_lines.append(f"<p>{escape_and_highlight_vuln(line)}</p>")
            idx += 1
            continue

        break

    return idx if idx != start_idx else start_idx


def parse_txt_content(txt_file: Path) -> str:
    content = txt_file.read_text(encoding="utf-8", errors="replace")
    content = clean_ansi(content)

    # Usuń SPECIFIC_ZALECAMY w środku treści
    content = re.sub(re.escape(SPECIFIC_ZALECAMY) + r"\.?\s*", "\n", content)

    # Usuń niechciane bloki
    content = re.sub(
        r"^[ \t]*([\w.-]+\.[a-z]{2,})[ \t]*\r?\n"
        r"-\s*Szanowni Państwo,[\s\S]*?"
        r"w ramach analizy bezpieczeństwa teleinformatycznego w Państwa domenie[^\n]*"
        r"zidentyfikowaliśmy obiekty, których wersja lub konfiguracja posiada znane podatności\.",
        "",
        content,
        flags=re.MULTILINE | re.IGNORECASE,
    )

    lines = content.splitlines()
    html_lines = []
    idx = 0
    toc_done = False
    first_numbered_point_done = False
    main_domain = ""
    pgp_present_in_txt = PGP_NOTICE in content

    def is_section_boundary(s: str) -> bool:
        s_strip = s.strip()
        if s_strip == "":
            return False
        return (
            s_strip.startswith("IP:")
            or bool(IP_IN_PARENS_LINE_RE.match(s_strip))  # compatibility: host (IP: x)
            or s_strip.startswith("Widoczne serwisy:")
            or s_strip.startswith("CVEs:")
            or s_strip.startswith("Domeny z brakującymi nagłówkami:")
            or s_strip.startswith("Spis treści:")
            or re.match(r"^\d+\.", s_strip)
            or s_strip.startswith("Zalecamy")
            or s_strip.startswith("Rekomendacje / uwagi:")
        )

    while idx < len(lines):
        raw_line = lines[idx]
        line = raw_line.strip()

        # Usuń domenę + Rekomendacje / uwagi:
        if re.match(r"^[\w.-]+\.[a-z]{2,}$", line):
            if idx + 1 < len(lines) and lines[idx + 1].strip() == "Rekomendacje / uwagi:":
                idx += 2
                continue

        # Artemis blocks
        new_idx = parse_artemis_blocks(lines, idx, html_lines)
        if new_idx != idx:
            idx = new_idx
            continue

        if line == "":
            idx += 1
            html_lines.append("")
            continue

        if re.match(
            r"^(Brak ustawienia|Wykryto podatnosc|Przestarzala wersja|Certyfikat niepodpisany|Wykryto phpinfo|FTP|WordPress login|Google API Key|cgi-bin|DKIM z krótkim kluczem kryptograficznym)",
            line,
            re.I,
        ):
            html_lines.append("<br>")

        if line == PGP_NOTICE or line == SPECIFIC_ZALECAMY:
            idx += 1
            continue

        # FIX: tolerate indentation for Zalecamy
        if line.lstrip().startswith("Zalecamy") and line != SPECIFIC_ZALECAMY:
            html_lines.append(f"<p><u>{escape_and_highlight_vuln(line.lstrip())}</u></p>")
            idx += 1
            continue

        # Bloki IP/Widoczne serwisy/CVEs (2 formats supported)
        if (
            idx + 2 < len(lines)
            and lines[idx + 1].strip().startswith("Widoczne serwisy:")
            and (lines[idx + 2].strip().startswith("CVEs:") or lines[idx + 2].strip().startswith("WPScan vulnerabilities:") or lines[idx + 2].strip().startswith("Wykryto przestarzałą"))
            and (
                lines[idx].strip().startswith("IP:")
                or bool(IP_IN_PARENS_LINE_RE.match(lines[idx].strip()))
            )
        ):
            first_line = lines[idx].strip()
            services_line = lines[idx + 1].strip()
            cves_line = lines[idx + 2].strip()

            # normalize "host (IP: x)" -> "IP: x (host)" for consistent display
            m_alt = IP_IN_PARENS_LINE_RE.match(first_line)
            if m_alt:
                host = m_alt.group(1).strip()
                ip = m_alt.group(2).strip()
                ip_line = f"IP: {ip} ({host})"
                # optional: keep main_domain updated
                if not main_domain:
                    main_domain = host
            else:
                ip_line = first_line
                m_std = IP_LINE_RE.match(first_line)
                if m_std:
                    ip = m_std.group(1).strip()
                    host = m_std.group(2).strip()
                    if not main_domain:
                        main_domain = host

            html_lines.extend(
                [
                    "<br>",
                    f"<p><strong>{escape_and_highlight_vuln(ip_line)}</strong></p>",
                    f"<p><strong>{escape_and_highlight_vuln(services_line)}</strong></p>",
                    f"<p><strong>{escape_and_highlight_vuln(cves_line)}</strong></p>",
                ]
            )
            idx += 3
            continue

        # Spis treści
        if "Spis treści:" in line and not toc_done:
            html_lines.append(f"<h1 class='toc'>{escape_and_highlight_vuln(line)}</h1>")
            idx += 1
            while idx < len(lines):
                nxt = lines[idx].strip()
                if not nxt or not re.match(r"^\d+\.", nxt):
                    break
                html_lines.append(f"<h1 class='toc'>{escape_and_highlight_vuln(nxt)}</h1>")
                idx += 1
            html_lines.append("<br>")
            toc_done = True
            continue

        if line.startswith("+"):
            html_lines.append("<br>")
            clean_line = line.lstrip("+").strip()
            html_lines.append(f"<p>{escape_and_highlight_vuln(clean_line)}</p>")
            idx += 1
            continue

        if line.startswith("*"):
            clean_line = line.lstrip("*").strip()
            html_lines.append(f"<p>&#8226; {escape_and_highlight_vuln(clean_line)}</p>")
            idx += 1
            continue

        # Domeny z brakującymi nagłówkami
        if line.startswith("Domeny z brakującymi nagłówkami:"):
            html_lines.append("<br>")
            html_lines.append(f"<p>{escape_and_highlight_vuln(line)}</p>")
            idx += 1
            first_domain_in_block = True
            while idx < len(lines):
                domain_line = lines[idx].strip()
                if not domain_line or (re.match(r"^\w", domain_line) and not domain_line.endswith(":")):
                    break
                if domain_line.endswith(":"):
                    if not first_domain_in_block:
                        html_lines.append("<br>")
                    html_lines.append(f"<p><strong>{escape_and_highlight_vuln(domain_line)}</strong></p>")
                    first_domain_in_block = False
                    idx += 1
                    while idx < len(lines):
                        header = lines[idx].strip()
                        if not header:
                            idx += 1
                            continue
                        if header.startswith("-"):
                            html_lines.append(f"<p>{escape_and_highlight_vuln(header)}</p>")
                            idx += 1
                        else:
                            break
                else:
                    idx += 1
            continue

        # --- Vulnerability section (CVE + WAS) ---
        if VULN_START_RE.match(line) or line.lower().startswith("rekomendacje:"):
            block_lines = []
            j = idx
            while j < len(lines):
                nxt_raw = lines[j]
                if j != idx and is_section_boundary(nxt_raw):
                    break
                block_lines.append(nxt_raw.rstrip("\n"))
                j += 1

            entries = []
            current_entry = []

            for bl in block_lines:
                if VULN_START_RE.match(bl):
                    if current_entry:
                        entries.append(current_entry)
                    current_entry = [bl]
                else:
                    if current_entry:
                        current_entry.append(bl)
                    else:
                        current_entry = [bl]

            if current_entry:
                entries.append(current_entry)

            html_lines.append("<ul>")
            for entry in entries:
                parts = []
                first = entry[0].strip()
                service_match = re.match(r"^([\w\.-]+\s*\(port\s*\d+\)):(.*)$", first, re.I)

                if service_match and len(entry) == 1:
                    sp = service_match.group(1).strip()
                    rest = service_match.group(2).strip()
                    if rest:
                        parts.append(
                            f"<strong>{escape_and_highlight_vuln(sp)}</strong>: {escape_and_highlight_vuln(rest)}"
                        )
                    else:
                        parts.append(f"<strong>{escape_and_highlight_vuln(sp)}</strong>:")
                else:
                    for line_part in entry:
                        stripped = line_part.rstrip()
                        if stripped.strip() == "":
                            parts.append("")
                        else:
                            if stripped.strip().lower().startswith("rekomendacje:"):
                                parts.append(f"<u>{escape_and_highlight_vuln(stripped.strip())}</u>")
                            else:
                                parts.append(escape_and_highlight_vuln(stripped))

                item_fragments = []
                for p in parts:
                    item_fragments.append("<br>" if p == "" else p)

                item_html = "<br>".join(item_fragments).strip()
                html_lines.append(f"<li>{item_html}</li>")
            html_lines.append("</ul>")

            idx = j
            continue

        # Numerowane nagłówki poza spisem treści
        if re.match(r"^\d+\.\s", line):
            if first_numbered_point_done:
                html_lines.append("<br>")
            html_lines.append(f"<h1>{escape_and_highlight_vuln(line)}</h1>")
            first_numbered_point_done = True
            idx += 1
            continue

        # Linie serwis (port N): ... poza blokami
        service_match = re.match(r"^([\w\.-]+\s*\(port\s*\d+\)):(.*)$", line, re.I)
        if service_match:
            sp, rest = service_match.groups()
            if rest.strip():
                html_lines.append(
                    f"<p><strong>{escape_and_highlight_vuln(sp.strip())}</strong>: {escape_and_highlight_vuln(rest.strip())}</p>"
                )
            else:
                html_lines.append(f"<p><strong>{escape_and_highlight_vuln(sp.strip())}</strong>:</p>")
            idx += 1
            continue

        html_lines.append(f"<p>{escape_and_highlight_vuln(line)}</p>")
        idx += 1

    # --- Ending (append once, no duplicates) ---
    spec_line_html = f"<p>{escape_and_highlight_vuln(SPECIFIC_ZALECAMY)}.</p>"
    if not any(SPECIFIC_ZALECAMY in ln for ln in html_lines):
        html_lines.append(spec_line_html)

    for ending_line in ENDING_LINES:
        if not any(ending_line in ln for ln in html_lines):
            html_lines.append(f"<p>{escape_and_highlight_vuln(ending_line)}</p>")

    if pgp_present_in_txt and not any(PGP_NOTICE in ln for ln in html_lines):
        html_lines.append(
            f"<p style='color:red; font-weight:bold; text-decoration:underline;'>"
            f"{escape_and_highlight_vuln(PGP_NOTICE)}</p>"
        )

    return "\n".join(html_lines)


def convert_txt_to_html(txt_file: Path, output_file: Path):
    body_content = parse_txt_content(txt_file)
    html_content = f"""<!DOCTYPE html>
<html lang='pl'>
<head>
<meta charset='UTF-8'>
<style>
body {{ font-family: Calibri, sans-serif; line-height: 1.5; margin: 20px; font-size: 11px; }}
ul {{ margin-left: 25px; margin-bottom: 15px; font-size: 11px; }}
li {{ margin-bottom: 10px; font-size: 11px; }}
p {{ margin: 5px 0; font-size: 11px; }}
h1 {{ font-size: 11px; margin: 5px 0; }}
h1.toc {{ font-size: 11px; }}
strong {{ font-weight: bold; font-size: 11px; }}
a {{ text-decoration: none; color: blue; font-size: 11px; }}
</style>
</head>
<body>
{body_content}
</body>
</html>"""
    output_file.write_text(html_content, encoding="utf-8")
    print(f"Wygenerowano {output_file}")


def _matches_any(patterns, *texts) -> bool:
    """True jeśli którykolwiek regex z patterns pasuje do któregokolwiek z tekstów."""
    for pat in patterns:
        for t in texts:
            if t and re.search(pat, t, re.IGNORECASE):
                return True
    return False


def _txt_has_pgp(txt_path: Path) -> bool:
    """Sprawdza po oryginalnym TXT czy ma być PGP (czyli czy zawiera PGP_NOTICE)."""
    try:
        raw = txt_path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return False
    raw = clean_ansi(raw)
    return PGP_NOTICE in raw


def _remove_pgp_lines(lines):
    """Usuwa wszystkie linie zawierające PGP_NOTICE (żeby nie było duplikatów / złych stanów)."""
    return [ln for ln in lines if PGP_NOTICE not in ln]


def _ensure_pgp_before_body_close(lines, add_pgp: bool):
    """
    Jeśli add_pgp=True, dopisuje czerwony PGP przed </body> (albo na końcu, jeśli </body> nie ma).
    Jeśli add_pgp=False, nie robi nic (zakładamy, że linie z PGP już usunięto).
    """
    if not add_pgp:
        return lines

    pgp_line = (
        "<p style='color:red; font-weight:bold; text-decoration:underline;'>"
        f"{escape_and_highlight_vuln(PGP_NOTICE)}</p>"
    )

    # jeśli już jest (np. ktoś ręcznie dodał), nie dodawaj drugi raz
    if any(PGP_NOTICE in ln for ln in lines):
        return lines

    # wstaw przed </body> jeśli istnieje
    for i, ln in enumerate(lines):
        if ln.strip().lower() == "</body>":
            return lines[:i] + [pgp_line] + lines[i:]

    # fallback: dopisz na końcu
    return lines + [pgp_line]


def main(folder_path: str):
    folder = Path(folder_path)
    if not folder.is_dir():
        print(f"Błąd: {folder} nie jest folderem")
        sys.exit(1)

    output_dir = folder / "html_reports"
    output_dir.mkdir(exist_ok=True)

    txt_files = list(folder.glob("*.txt"))
    if not txt_files:
        print("Nie znaleziono plików .txt w folderze")
        sys.exit(0)

    for txt_file in txt_files:
        output_file = output_dir / f"{txt_file.stem}.html"
        convert_txt_to_html(txt_file, output_file)

    # --- sed cleanup on all generated HTML (optional) ---
    sed_cmd = (
        r"sed -E -i "
        r"'s|(<br>){3,}Jeżeli któreś z podatności nie dotyczą podmiotu, "
        r"prosimy o informację zwrotną wraz z wyjaśnieniem\.(<br>){2,}"
        r"Prosimy pamiętać, że skanowanie jest rozłożone w czasie\.(<br>){0,}"
        r"(Jednocześnie przypominamy o rekomendowanej formie komunikacji z wykorzystaniem "
        r"szyfrowania wiadomości PGP\.)?||g' "
        f"{output_dir}/*.html"
    )
    subprocess.run(sed_cmd, shell=True, check=False)

    # Regexy domen/identyfikatorów raportów, które NIE MAJĄ mieć PGP.
    # Przykład:
    # bez_pgp_patterns = [r"\bexample\.com\b", r"^internal-.*"]
    bez_pgp_patterns = []

    for html_file in output_dir.glob("*.html"):
        lines = html_file.read_text(encoding="utf-8").splitlines()
        html_text = "\n".join(lines)
        file_base = html_file.stem

        # Odpowiadający TXT (źródło prawdy dla "czy w ogóle ma być PGP")
        txt_path = folder / f"{file_base}.txt"
        should_have_pgp = _txt_has_pgp(txt_path)

        # Jeśli regex matchuje -> NIE dodawaj PGP
        exclude_pgp = _matches_any(bez_pgp_patterns, file_base, html_text)

        # Zawsze usuń istniejące PGP linie (żeby uniknąć złych stanów/duplikacji)
        lines = _remove_pgp_lines(lines)

        # Jeśli ending już jest, to nie duplikujemy go, ale nadal naprawiamy PGP
        ending_already_present = any(
            "Jeżeli któreś z podatności nie dotyczą podmiotu" in ln for ln in lines
        )

        if not ending_already_present:
            # Cut from SPECIFIC_ZALECAMY if exists, then re-append a clean ending
            try:
                start_index = next(i for i, ln in enumerate(lines) if SPECIFIC_ZALECAMY in ln)
                lines = lines[:start_index]
            except StopIteration:
                pass

            lines.append(f"<p>{escape_and_highlight_vuln(SPECIFIC_ZALECAMY)}.</p>")
            lines.append(
                "<p>Jeżeli któreś z podatności nie dotyczą podmiotu, prosimy o informację zwrotną wraz z wyjaśnieniem. "
                "Pozwoli to na przeanalizowanie takiego przypadku przez nas i ewentualne wykluczenie podatności z przyszłych raportów.</p>"
            )
            lines.append(
                "<p>Prosimy pamiętać, że skanowanie jest rozłożone w czasie. Tym samym, ze względu na czas trwania procesu, "
                "może się okazać, że część problemów opisanych wyżej została już przez Państwa rozwiązana.</p>"
            )

        # Dodaj PGP tylko gdy:
        # - TXT ma PGP_NOTICE
        # - i NIE ma matcha w bez_pgp_patterns
        add_pgp = should_have_pgp and (not exclude_pgp)
        lines = _ensure_pgp_before_body_close(lines, add_pgp=add_pgp)

        # ensure closing tags exist once
        if not any(l.strip().lower() == "</body>" for l in lines):
            lines.append("</body>")
        if not any(l.strip().lower() == "</html>" for l in lines):
            lines.append("</html>")

        html_file.write_text("\n".join(lines), encoding="utf-8")

    print(f"Wszystkie pliki przetworzone. Wyniki w: {output_dir}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Użycie: python3 script.py folder_z_plikami_txt")
        sys.exit(1)
    main(sys.argv[1])

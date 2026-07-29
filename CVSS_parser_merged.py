#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

# Matches CVE tokens not already annotated like "CVE-.... (..)"
CVE_PATTERN = re.compile(r"\b(CVE-\d{4}-\d+)\b(?!\s*\()", re.IGNORECASE)
CACHE_FILE = "cvss_cache.json"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/127.0.0.0 Safari/537.36"
    )
}

# -------------------------------
# 🔹 Cache (dla szybkości)
# -------------------------------
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


# -------------------------------
# 🔹 Pomocnicze
# -------------------------------
def severity_from_score(score: float):
    if score is None:
        return "brak_danych"
    if score >= 9.0:
        return "krytyczne"
    elif score >= 7.0:
        return "wysokie"
    elif score >= 4.0:
        return "średnie"
    elif score > 0.0:
        return "niskie"
    return "brak_danych"


def severity_order(level: str) -> int:
    order = {"krytyczne": 1, "wysokie": 2, "średnie": 3, "niskie": 4, "brak_danych": 5}
    return order.get(level, 6)


# -------------------------------
# 🔹 Główne pobieranie CVSS
# -------------------------------
def extract_cvss_score(cve: str, cache: dict):
    """
    Szuka CVSS v3 (wszystkie warianty). Jeśli nie znajdzie, dopiero wtedy szuka CVSS v2.
    """
    cve = cve.upper()

    if cve in cache:
        return cache[cve]

    url = f"https://nvd.nist.gov/vuln/detail/{cve}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code != 200:
            cache[cve] = None
            return None

        soup = BeautifulSoup(r.text, "html.parser")

        # --- Najpierw CVSS v3 ---
        selectors_v3 = [
            "a[data-testid='vuln-cvss3-panel-score']",
            "a.label.label-critical",
            "a.label.label-danger",
            "a.label.label-warning",
            "a.label.label-info",
            "span.label.label-critical",
            "span.label.label-danger",
            "span.label.label-warning",
            "span.label.label-info",
            "div.label.label-critical",
            "div.label.label-danger",
            "div.label.label-warning",
            "div.label.label-info",
            "div#Cvss3NistCalculatorAnchor",
        ]

        for sel in selectors_v3:
            el = soup.select_one(sel)
            if el and el.text:
                m = re.search(r"(\d+\.\d+)", el.text)
                if m:
                    val = float(m.group(1))
                    cache[cve] = val
                    return val

        # --- Jeśli CVSS v3 brak, szukamy CVSS v2 ---
        selectors_v2 = [
            "a#Cvss2CalculatorAnchor",
            "div#Cvss2CalculatorAnchor",
            "span#Cvss2CalculatorAnchor",
        ]
        for sel in selectors_v2:
            el = soup.select_one(sel)
            if el and el.text:
                m = re.search(r"(\d+\.\d+)", el.text)
                if m:
                    val = float(m.group(1))
                    cache[cve] = val
                    return val

        # --- Fallback (regex) ---
        m = re.search(r"(\d+\.\d+)\s*(LOW|MEDIUM|HIGH|CRITICAL)", r.text, re.IGNORECASE)
        if m:
            val = float(m.group(1))
            cache[cve] = val
            return val

    except Exception:
        pass

    cache[cve] = None
    return None


# -------------------------------
# 🔹 Granice sekcji / bloków (compat with your reports)
# -------------------------------
IP_STD_LINE_RE = re.compile(r"^\s*IP:\s*\d{1,3}(?:\.\d{1,3}){3}\s*\([^)]+\)\s*$", re.IGNORECASE)
IP_ALT_LINE_RE = re.compile(r"^\s*[^()]+\s*\(IP:\s*\d{1,3}(?:\.\d{1,3}){3}\)\s*$", re.IGNORECASE)

def is_block_boundary(line: str) -> bool:
    """
    Boundary means: this line starts a new report section, so CVE entry should stop before it.
    """
    s = (line or "").strip()
    if not s:
        return False

    if re.match(r"^\d+\.", s):
        return True

    # Both variants of host header
    if s.startswith("IP:") or IP_STD_LINE_RE.match(s) or IP_ALT_LINE_RE.match(s):
        return True

    # Common section headers in your TXT reports
    starters = (
        "Widoczne serwisy:",
        "CVEs:",
        "WPScan vulnerabilities:",
        "Domeny z brakującymi nagłówkami:",
        "Spis treści:",
        "Jeżeli któreś",
        "Prosimy pamiętać",
        "Zalecamy",
        "Rekomendacje / uwagi:",
        "Rekomendacje:",
    )
    return s.startswith(starters)


# -------------------------------
# 🔹 Sortowanie bloków CVE (bez psucia sekcji)
# -------------------------------
def sort_cve_blocks_in_text(text: str, cve_scores: dict) -> str:
    """
    Sortuje tylko "ciągi" wpisów CVE (linie zaczynające się od CVE-... z opcjonalnymi kolejnymi liniami),
    ale przerywa, gdy natrafi na granicę sekcji.
    """
    lines = text.splitlines(keepends=True)
    out_lines = []
    i = 0
    n = len(lines)

    while i < n:
        if re.match(r"^\s*CVE-\d{4}-\d+", lines[i], re.IGNORECASE):
            block_entries = []

            # collect consecutive CVE entries
            while i < n and re.match(r"^\s*CVE-\d{4}-\d+", lines[i], re.IGNORECASE):
                entry_lines = [lines[i]]
                i += 1

                # consume continuation lines until next CVE or boundary
                while i < n and not re.match(r"^\s*CVE-\d{4}-\d+", lines[i], re.IGNORECASE) and not is_block_boundary(lines[i]):
                    entry_lines.append(lines[i])
                    i += 1

                block_entries.append("".join(entry_lines))

                # stop if we hit a boundary immediately after an entry
                if i < n and is_block_boundary(lines[i]):
                    break

            def extract_score(entry_text):
                m = re.search(r"CVE-\d{4}-\d+", entry_text, re.IGNORECASE)
                if m:
                    return cve_scores.get(m.group(0).upper())
                return None

            def extract_severity(entry_text):
                m = re.search(r"CVE-\d{4}-\d+", entry_text, re.IGNORECASE)
                if m:
                    return severity_from_score(cve_scores.get(m.group(0).upper()))
                return "brak_danych"

            def sort_key(entry):
                s = extract_score(entry)
                score_val = s if s is not None else -1.0
                sev = extract_severity(entry)
                return (-score_val, severity_order(sev))

            block_entries.sort(key=sort_key)

            for be in block_entries:
                if not be.endswith("\n"):
                    be += "\n"
                out_lines.append(be)
                # keep spacing nice
                if not out_lines[-1].endswith("\n\n"):
                    out_lines.append("\n")
            continue

        out_lines.append(lines[i])
        i += 1

    result = "".join(out_lines)
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result


# -------------------------------
# 🔹 Przetwarzanie pojedynczego pliku
# -------------------------------
def process_file(path, cache, threshold):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # Collect CVEs (case-insensitive)
    cves = set(m.group(1).upper() for m in CVE_PATTERN.finditer(content))
    cve_scores = {}

    for cve in tqdm(sorted(cves), desc=f"Pobieranie CVSS dla {os.path.basename(path)}", leave=False):
        cve_scores[cve] = extract_cvss_score(cve, cache)
        time.sleep(0.15)  # throttle

    lines = content.splitlines(keepends=True)
    new_lines = []

    last_removed_cve = False
    skip_continuation_after_removed = False

    for line in lines:
        # If we previously removed a CVE line, optionally skip its continuation lines until boundary/new CVE
        if skip_continuation_after_removed:
            if re.match(r"^\s*CVE-\d{4}-\d+", line, re.IGNORECASE) or is_block_boundary(line):
                skip_continuation_after_removed = False
            else:
                # continuation line (indented / descriptive) -> drop
                continue

        match = CVE_PATTERN.search(line)
        if match:
            cve = match.group(1).upper()
            score = cve_scores.get(cve)
            severity = severity_from_score(score)

            # remove if below threshold (only if we have score)
            if score is not None and score < threshold:
                last_removed_cve = True
                skip_continuation_after_removed = True
                continue

            score_str = f"{score:.1f}" if score is not None else "brak"

            # annotate once
            if not re.search(rf"{re.escape(cve)}\s*\([^)]+\)", line, re.IGNORECASE):
                line = re.sub(
                    rf"{re.escape(cve)}\b(?!\s*\()",
                    f"{cve} ({severity}, {score_str})",
                    line,
                    count=1,
                    flags=re.IGNORECASE,
                )

            new_lines.append(line)
            last_removed_cve = False
            continue

        # If the last CVE was removed, avoid leaving orphan recommendation header lines
        if last_removed_cve:
            s = line.strip().lower()
            if s.startswith("rekomendacje:") or s.startswith("rekomendacje / uwagi:"):
                continue

        new_lines.append(line)

    final_text = "".join(new_lines)
    final_text = sort_cve_blocks_in_text(final_text, cve_scores)

    with open(path, "w", encoding="utf-8") as f:
        f.write(final_text)


# -------------------------------
# 🔹 Main
# -------------------------------
def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else input("Ścieżka do folderu: ").strip()
    if not os.path.isdir(folder):
        sys.exit("❌ Błąd: folder nie istnieje")

    threshold = float(input("Podaj próg CVSS (0–10): ").strip())
    cache = load_cache()

    txt_files = [f for f in os.listdir(folder) if f.lower().endswith(".txt")]
    for filename in tqdm(txt_files, desc="Przetwarzanie plików", unit="plik"):
        process_file(os.path.join(folder, filename), cache, threshold)
        save_cache(cache)

    save_cache(cache)
    print("\n✅ Zakończono przetwarzanie wszystkich plików.")


if __name__ == "__main__":
    main()

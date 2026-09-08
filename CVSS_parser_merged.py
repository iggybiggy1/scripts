#!/usr/bin/env python3

import os
import re
import sys
import json
import time
from typing import Optional, Dict, Any, Tuple

import requests
from tqdm import tqdm


# ============================================================
# KONFIGURACJA
# ============================================================

CACHE_FILE = "cvss_cache.json"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_API_URL = "https://cveawg.mitre.org/api/cve"

REQUEST_TIMEOUT = 20
MAX_RETRIES = 3

# Opcjonalnie:
# export NVD_API_KEY="twoj-klucz"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()


# ============================================================
# REGEX
# ============================================================

# Celowo NIE ignorujemy CVE posiadających już adnotację.
# Dzięki temu:
#
# CVE-2023-38709 (brak_danych, brak):
#
# może zostać poprawione na:
#
# CVE-2023-38709 (wysoka, 7.3):
#
CVE_PATTERN = re.compile(
    r"\b(CVE-\d{4}-\d{4,})\b",
    re.IGNORECASE
)

# Stara adnotacja wygenerowana przez skrypt:
# CVE-2023-38709 (brak_danych, brak)
# CVE-2023-38709 (wysokie, 7.5)
# itd.
CVE_ANNOTATION_PATTERN = re.compile(
    r"\b(CVE-\d{4}-\d{4,})\b"
    r"(?:\s*\("
    r"(?:"
    r"krytyczne|krytyczna|"
    r"wysokie|wysoka|"
    r"srednie|średnie|srednia|średnia|"
    r"niskie|niska|"
    r"brak_danych"
    r")"
    r"\s*,\s*"
    r"(?:\d+(?:\.\d+)?|brak)"
    r"\))?",
    re.IGNORECASE
)


# ============================================================
# HTTP
# ============================================================

session = requests.Session()

session.headers.update({
    "User-Agent": (
        "Mozilla/5.0 "
        "(compatible; CVSS-report-enricher/2.0; "
        "+https://nvd.nist.gov/)"
    ),
    "Accept": "application/json",
})

if NVD_API_KEY:
    session.headers["apiKey"] = NVD_API_KEY


# ============================================================
# CACHE
# ============================================================

def load_cache() -> Dict[str, Any]:
    if not os.path.isfile(CACHE_FILE):
        return {}

    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            return data

    except Exception as exc:
        print(
            f"[!] Nie można odczytać cache {CACHE_FILE}: {exc}",
            file=sys.stderr
        )

    return {}


def save_cache(cache: Dict[str, Any]) -> None:
    tmp_file = CACHE_FILE + ".tmp"

    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(
                cache,
                f,
                ensure_ascii=False,
                indent=2
            )

        os.replace(tmp_file, CACHE_FILE)

    except Exception as exc:
        print(
            f"[!] Nie można zapisać cache: {exc}",
            file=sys.stderr
        )


def get_cached_score(
    cve: str,
    cache: Dict[str, Any]
) -> Optional[float]:
    """
    Obsługuje zarówno nowy cache:

        {
          "CVE-...": {
             "score": 7.3,
             "version": "3.1",
             "source": "CVE-CNA"
          }
        }

    jak i stary:

        {
          "CVE-...": 7.3
        }

    Stary wpis null / None NIE jest uznawany za poprawny cache,
    ponieważ mógł powstać wskutek chwilowego błędu HTTP.
    """

    if cve not in cache:
        return None

    value = cache[cve]

    # stary format
    if isinstance(value, (int, float)):
        score = float(value)

        if 0.0 <= score <= 10.0:
            return score

        return None

    # null ze starego skryptu -> ponów pobieranie
    if value is None:
        return None

    # nowy format
    if isinstance(value, dict):
        score = value.get("score")

        if isinstance(score, (int, float)):
            score = float(score)

            if 0.0 <= score <= 10.0:
                return score

    return None


# ============================================================
# KLASYFIKACJA CVSS
# ============================================================

def severity_from_score(score: Optional[float]) -> str:
    """
    Klasyfikacja:

    0.0 - 3.9 -> niska
    4.0 - 6.9 -> srednia
    7.0 - 8.9 -> wysoka
    9.0 - 10.0 -> krytyczna

    Użytkownik wymaga czterech kategorii, dlatego również
    wynik 0.0 klasyfikujemy tutaj jako 'niska'.
    """

    if score is None:
        return "brak_danych"

    if score >= 9.0:
        return "krytyczna"

    if score >= 7.0:
        return "wysoka"

    if score >= 4.0:
        return "srednia"

    return "niska"


def severity_order(level: str) -> int:
    return {
        "krytyczna": 1,
        "wysoka": 2,
        "srednia": 3,
        "niska": 4,
        "brak_danych": 5,
    }.get(level.lower(), 6)


def valid_score(value: Any) -> Optional[float]:
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None

    if 0.0 <= value <= 10.0:
        return value

    return None


# ============================================================
# REQUEST Z RETRY
# ============================================================

def request_json(
    url: str,
    params: Optional[dict] = None
) -> Optional[dict]:

    for attempt in range(1, MAX_RETRIES + 1):

        try:
            response = session.get(
                url,
                params=params,
                timeout=REQUEST_TIMEOUT
            )

            # Rate limit
            if response.status_code == 429:
                wait = min(1 * attempt, 20)

                print(
                    f"\n[!] HTTP 429 - rate limit. "
                    f"Ponawiam za {wait}s...",
                    file=sys.stderr
                )

                time.sleep(wait)
                continue

            # chwilowy problem po stronie serwera
            if response.status_code in (
                500,
                502,
                503,
                504
            ):
                time.sleep(2 * attempt)
                continue

            response.raise_for_status()

            return response.json()

        except requests.RequestException as exc:

            if attempt == MAX_RETRIES:
                print(
                    f"\n[!] Błąd HTTP dla {url}: {exc}",
                    file=sys.stderr
                )
                return None

            time.sleep(2 * attempt)

        except json.JSONDecodeError:
            print(
                f"\n[!] Niepoprawny JSON: {url}",
                file=sys.stderr
            )
            return None

    return None


# ============================================================
# NVD API
# ============================================================

def metric_priority(metric: Dict[str, Any]) -> int:
    """
    Preferujemy oficjalną ocenę NVD/NIST.

    Jeżeli jej nie ma, dopuszczamy wynik CNA znajdujący się
    w rekordzie NVD.
    """

    source = str(metric.get("source", "")).lower()
    metric_type = str(metric.get("type", "")).lower()

    if "nvd@nist.gov" in source:
        return 0

    if metric_type == "primary":
        return 1

    return 2


def extract_score_from_nvd_metrics(
    metrics: Dict[str, Any]
) -> Optional[Tuple[float, str, str]]:

    """
    Kolejność wersji:

        CVSS 4.0
        CVSS 3.1
        CVSS 3.0
        CVSS 2.0

    W obrębie danej wersji:
        NVD/NIST > Primary > pozostałe źródła.
    """

    versions = [
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]

    for key, version in versions:

        entries = metrics.get(key, [])

        if not isinstance(entries, list):
            continue

        entries = sorted(
            entries,
            key=metric_priority
        )

        for metric in entries:

            if not isinstance(metric, dict):
                continue

            cvss_data = metric.get(
                "cvssData",
                {}
            )

            if not isinstance(cvss_data, dict):
                continue

            score = valid_score(
                cvss_data.get("baseScore")
            )

            if score is None:
                continue

            source = str(
                metric.get(
                    "source",
                    "NVD"
                )
            )

            return score, version, source

    return None


def get_cvss_from_nvd(
    cve: str
) -> Optional[Tuple[float, str, str]]:

    data = request_json(
        NVD_API_URL,
        params={
            "cveId": cve
        }
    )

    if not data:
        return None

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )

    if not vulnerabilities:
        return None

    for item in vulnerabilities:

        if not isinstance(item, dict):
            continue

        cve_data = item.get(
            "cve",
            {}
        )

        if not isinstance(cve_data, dict):
            continue

        record_id = str(
            cve_data.get("id", "")
        ).upper()

        if record_id != cve:
            continue

        metrics = cve_data.get(
            "metrics",
            {}
        )

        if not isinstance(metrics, dict):
            continue

        result = extract_score_from_nvd_metrics(
            metrics
        )

        if result:
            return result

    return None


# ============================================================
# CVE.ORG / CNA FALLBACK
# ============================================================

def extract_score_from_cve_metric(
    metric: Dict[str, Any]
) -> Optional[Tuple[float, str]]:

    """
    Obsługiwane formaty CVE JSON 5.x.
    """

    versions = [
        ("cvssV4_0", "4.0"),
        ("cvssV3_1", "3.1"),
        ("cvssV3_0", "3.0"),
        ("cvssV2_0", "2.0"),
    ]

    for key, version in versions:

        cvss = metric.get(key)

        if not isinstance(cvss, dict):
            continue

        score = valid_score(
            cvss.get("baseScore")
        )

        if score is not None:
            return score, version

    return None


def search_cve_container_metrics(
    container: Dict[str, Any],
    source_name: str
) -> Optional[Tuple[float, str, str]]:

    metrics = container.get(
        "metrics",
        []
    )

    if not isinstance(metrics, list):
        return None

    # Najpierw wybierz najwyższą dostępną wersję CVSS.
    candidates = []

    version_priority = {
        "4.0": 0,
        "3.1": 1,
        "3.0": 2,
        "2.0": 3,
    }

    for metric in metrics:

        if not isinstance(metric, dict):
            continue

        result = extract_score_from_cve_metric(
            metric
        )

        if result is None:
            continue

        score, version = result

        candidates.append(
            (
                version_priority.get(
                    version,
                    99
                ),
                score,
                version
            )
        )

    if not candidates:
        return None

    candidates.sort(
        key=lambda x: x[0]
    )

    _, score, version = candidates[0]

    return score, version, source_name


def get_cvss_from_cve_org(
    cve: str
) -> Optional[Tuple[float, str, str]]:

    url = f"{CVE_API_URL}/{cve}"

    data = request_json(url)

    if not data:
        return None

    containers = data.get(
        "containers",
        {}
    )

    if not isinstance(containers, dict):
        return None

    # --------------------------------------------------------
    # 1. CNA jest podstawowym źródłem CVE
    # --------------------------------------------------------

    cna = containers.get("cna")

    if isinstance(cna, dict):

        result = search_cve_container_metrics(
            cna,
            "CVE-CNA"
        )

        if result:
            return result

    # --------------------------------------------------------
    # 2. ADP jako dodatkowy fallback
    # --------------------------------------------------------

    adp_list = containers.get(
        "adp",
        []
    )

    if isinstance(adp_list, list):

        for adp in adp_list:

            if not isinstance(adp, dict):
                continue

            provider = adp.get(
                "providerMetadata",
                {}
            )

            org_name = ""

            if isinstance(provider, dict):
                org_name = str(
                    provider.get(
                        "shortName",
                        ""
                    )
                )

            source = (
                f"CVE-ADP:{org_name}"
                if org_name
                else "CVE-ADP"
            )

            result = search_cve_container_metrics(
                adp,
                source
            )

            if result:
                return result

    return None


# ============================================================
# GŁÓWNA FUNKCJA POBIERANIA CVSS
# ============================================================

def extract_cvss_score(
    cve: str,
    cache: Dict[str, Any]
) -> Optional[float]:

    cve = cve.upper()

    # --------------------------------------------------------
    # CACHE
    # --------------------------------------------------------

    cached = get_cached_score(
        cve,
        cache
    )

    if cached is not None:
        return cached

    # --------------------------------------------------------
    # NVD
    # --------------------------------------------------------

    result = get_cvss_from_nvd(cve)

    if result:

        score, version, source = result

        cache[cve] = {
            "score": score,
            "version": version,
            "source": source,
        }

        return score

    # --------------------------------------------------------
    # CVE.ORG / CNA
    # --------------------------------------------------------

    result = get_cvss_from_cve_org(cve)

    if result:

        score, version, source = result

        cache[cve] = {
            "score": score,
            "version": version,
            "source": source,
        }

        return score

    # --------------------------------------------------------
    # WAŻNE:
    #
    # NIE zapisujemy None do cache.
    #
    # Brak wyniku może wynikać np. z:
    # - timeoutu,
    # - chwilowej awarii NVD,
    # - rate limit,
    # - chwilowej awarii CVE.org.
    #
    # Kolejne uruchomienie powinno więc spróbować ponownie.
    # --------------------------------------------------------

    return None


# ============================================================
# GRANICE BLOKÓW RAPORTU
# ============================================================

IP_STD_LINE_RE = re.compile(
    r"^\s*IP:\s*"
    r"\d{1,3}(?:\.\d{1,3}){3}"
    r"\s*\([^)]+\)\s*$",
    re.IGNORECASE
)

IP_ALT_LINE_RE = re.compile(
    r"^\s*[^()]+\s*"
    r"\(IP:\s*"
    r"\d{1,3}(?:\.\d{1,3}){3}"
    r"\)\s*$",
    re.IGNORECASE
)


def is_block_boundary(line: str) -> bool:

    s = (line or "").strip()

    if not s:
        return False

    if re.match(
        r"^\d+\.",
        s
    ):
        return True

    if (
        s.startswith("IP:")
        or IP_STD_LINE_RE.match(s)
        or IP_ALT_LINE_RE.match(s)
    ):
        return True

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
        "Podatności wykryte",
    )

    return s.startswith(starters)


# ============================================================
# SORTOWANIE CVE
# ============================================================

def get_cve_from_text(
    text: str
) -> Optional[str]:

    match = CVE_PATTERN.search(text)

    if match:
        return match.group(1).upper()

    return None


def sort_cve_blocks_in_text(
    text: str,
    cve_scores: Dict[str, Optional[float]]
) -> str:

    lines = text.splitlines(
        keepends=True
    )

    output = []

    i = 0
    count = len(lines)

    while i < count:

        if re.match(
            r"^\s*CVE-\d{4}-\d{4,}",
            lines[i],
            re.IGNORECASE
        ):

            entries = []

            while (
                i < count
                and re.match(
                    r"^\s*CVE-\d{4}-\d{4,}",
                    lines[i],
                    re.IGNORECASE
                )
            ):

                entry_lines = [
                    lines[i]
                ]

                i += 1

                while i < count:

                    # następne CVE
                    if re.match(
                        r"^\s*CVE-\d{4}-\d{4,}",
                        lines[i],
                        re.IGNORECASE
                    ):
                        break

                    # nowa sekcja
                    if is_block_boundary(
                        lines[i]
                    ):
                        break

                    entry_lines.append(
                        lines[i]
                    )

                    i += 1

                entries.append(
                    "".join(entry_lines)
                )

                if (
                    i < count
                    and is_block_boundary(
                        lines[i]
                    )
                ):
                    break

            def sort_key(
                entry: str
            ):

                cve = get_cve_from_text(
                    entry
                )

                score = (
                    cve_scores.get(cve)
                    if cve
                    else None
                )

                severity = severity_from_score(
                    score
                )

                # największy CVSS pierwszy
                score_sort = (
                    score
                    if score is not None
                    else -1.0
                )

                return (
                    -score_sort,
                    severity_order(
                        severity
                    )
                )

            entries.sort(
                key=sort_key
            )

            for entry in entries:

                output.append(
                    entry.rstrip("\n") + "\n"
                )

                output.append("\n")

            continue

        output.append(
            lines[i]
        )

        i += 1

    result = "".join(output)

    # maksymalnie jedna pusta linia
    result = re.sub(
        r"\n{3,}",
        "\n\n",
        result
    )

    return result


# ============================================================
# AKTUALIZOWANIE WPISU CVE
# ============================================================

def annotate_cve_line(
    line: str,
    cve_scores: Dict[str, Optional[float]]
) -> str:

    """
    Zastępuje zarówno:

        CVE-2023-38709

    jak i:

        CVE-2023-38709 (brak_danych, brak)

    oraz:

        CVE-2023-38709 (srednie, 5.0)

    nową, aktualną adnotacją.
    """

    def replacement(
        match: re.Match
    ) -> str:

        cve = match.group(1).upper()

        score = cve_scores.get(
            cve
        )

        severity = severity_from_score(
            score
        )

        score_string = (
            f"{score:.1f}"
            if score is not None
            else "brak"
        )

        return (
            f"{cve} "
            f"({severity}, {score_string})"
        )

    return CVE_ANNOTATION_PATTERN.sub(
        replacement,
        line
    )


# ============================================================
# PRZETWARZANIE PLIKU
# ============================================================

def process_file(
    path: str,
    cache: Dict[str, Any],
    threshold: float
) -> None:

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        content = f.read()

    # --------------------------------------------------------
    # ZBIERZ WSZYSTKIE CVE
    #
    # Również te już opisane:
    #
    # CVE-... (brak_danych, brak)
    # --------------------------------------------------------

    cves = sorted({
        match.group(1).upper()
        for match
        in CVE_PATTERN.finditer(content)
    })

    if not cves:
        return

    cve_scores: Dict[
        str,
        Optional[float]
    ] = {}

    for cve in tqdm(
        cves,
        desc=(
            f"CVSS: "
            f"{os.path.basename(path)}"
        ),
        leave=False
    ):

        score = extract_cvss_score(
            cve,
            cache
        )

        cve_scores[cve] = score

        # NVD rate limiting:
        #
        # z API key możemy działać szybciej.
        #
        # Bez API key robimy niewielkie opóźnienie.
        if NVD_API_KEY:
            time.sleep(0.15)
        else:
            time.sleep(0.7)

    # --------------------------------------------------------
    # PRZETWARZANIE LINII
    # --------------------------------------------------------

    lines = content.splitlines(
        keepends=True
    )

    new_lines = []

    skip_continuation = False

    for line in lines:

        # ----------------------------------------------------
        # Jeżeli usunęliśmy CVE poniżej threshold,
        # usuń również należący do niego opis.
        # ----------------------------------------------------

        if skip_continuation:

            if re.match(
                r"^\s*CVE-\d{4}-\d{4,}",
                line,
                re.IGNORECASE
            ):
                skip_continuation = False

            elif is_block_boundary(line):
                skip_continuation = False

            else:
                continue

        match = CVE_PATTERN.search(
            line
        )

        if match:

            cve = match.group(1).upper()

            score = cve_scores.get(
                cve
            )

            # -----------------------------------------------
            # threshold
            # -----------------------------------------------

            if (
                score is not None
                and score < threshold
            ):
                skip_continuation = True
                continue

            # -----------------------------------------------
            # Zawsze aktualizujemy adnotację.
            #
            # To naprawia:
            #
            # (brak_danych, brak)
            # -----------------------------------------------

            line = annotate_cve_line(
                line,
                cve_scores
            )

            new_lines.append(
                line
            )

            continue

        new_lines.append(
            line
        )

    final_text = "".join(
        new_lines
    )

    final_text = sort_cve_blocks_in_text(
        final_text,
        cve_scores
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:
        f.write(final_text)


# ============================================================
# INPUT
# ============================================================

def get_threshold() -> float:

    while True:

        try:
            raw = input(
                "Podaj próg CVSS (0.0-10.0): "
            ).strip()

            value = float(
                raw.replace(",", ".")
            )

            if not 0.0 <= value <= 10.0:
                raise ValueError

            return value

        except ValueError:
            print(
                "Błąd: podaj liczbę "
                "od 0.0 do 10.0."
            )


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) > 1:

        folder = sys.argv[1]

    else:

        folder = input(
            "Ścieżka do folderu: "
        ).strip()

    folder = os.path.abspath(
        os.path.expanduser(folder)
    )

    if not os.path.isdir(folder):
        sys.exit(
            f"Błąd: folder nie istnieje: "
            f"{folder}"
        )

    threshold = get_threshold()

    cache = load_cache()

    txt_files = sorted([
        filename
        for filename
        in os.listdir(folder)
        if filename.lower().endswith(
            ".txt"
        )
    ])

    if not txt_files:

        print(
            "Brak plików .txt "
            "w podanym folderze."
        )

        return

    print(
        f"\nZnaleziono plików TXT: "
        f"{len(txt_files)}"
    )

    print(
        f"Próg CVSS: {threshold:.1f}"
    )

    print(
        "Źródła CVSS: "
        "NVD API -> CVE.org/CNA\n"
    )

    for filename in tqdm(
        txt_files,
        desc="Przetwarzanie",
        unit="plik"
    ):

        path = os.path.join(
            folder,
            filename
        )

        try:

            process_file(
                path,
                cache,
                threshold
            )

            save_cache(
                cache
            )

        except Exception as exc:

            print(
                f"\n[!] Błąd podczas "
                f"przetwarzania "
                f"{filename}: {exc}",
                file=sys.stderr
            )

    save_cache(
        cache
    )

    print(
        "\nZakończono przetwarzanie."
    )


if __name__ == "__main__":
    main()

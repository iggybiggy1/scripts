#!/usr/bin/env python3
"""
Automatyzacja uruchamiania raportów Nuclei i CVE (wersja MERGED).
Użytkownik wybiera folder zawierający:
- folder CVE/
- plik domeny.txt
- opcjonalnie plik nuclei_grouped.txt
- opcjonalnie plik nuclei_scan.txt

Skrypt uruchamia kolejno:
1. nuclei_parser_merged.py (tylko jeśli nuclei_grouped.txt nie istnieje)
2. raport_parser_merged.py
3. CVSS_parser_merged.py
4. html_raport_parser_merged.py

Po wygenerowaniu HTML uruchamia sed, aby usunąć powtarzające się linie w plikach HTML.
"""

import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog


def run_script(script_path, *args):
    """Uruchamia podany skrypt Python z argumentami."""
    print(f"\n➡️  Uruchamiam: {os.path.basename(script_path)} {' '.join(args)}")
    result = subprocess.run([sys.executable, script_path, *args])
    if result.returncode != 0:
        print(f"❌ Błąd przy uruchamianiu {script_path}. Kończę.")
        sys.exit(result.returncode)
    print(f"✅ Zakończono: {os.path.basename(script_path)}\n")


def run_sed_in_html_reports(html_folder):
    """Uruchamia komendę sed we wskazanym folderze HTML."""
    if not os.path.isdir(html_folder):
        print(f"⚠️ Folder HTML nie istnieje: {html_folder}")
        return

    print(f"\n➡️  Uruchamiam sed w folderze: {html_folder}")

    sed_command = (
        r"sed -i 's|<br><br><br><br><br>Jeżeli któreś z podatności nie dotyczą podmiotu, "
        r"prosimy o informację zwrotną wraz z wyjaśnieniem.<br><br><br>Prosimy pamiętać, że "
        r"skanowanie jest rozłożone w czasie.<br><br><br>Jednocześnie przypominamy o "
        r"rekomendowanej formie komunikacji z wykorzystaniem szyfrowania wiadomości PGP.||g' *.html"
    )
    subprocess.run(sed_command, shell=True, cwd=html_folder)
    print(f"✅ Sed wykonane w {html_folder}\n")


def main():
    print("=== 🔗 Automatyzacja raportów Nuclei i CVE (MERGED) ===\n")

    # --- Pobranie folderu z danymi od użytkownika przez GUI ---
    root = tk.Tk()
    root.withdraw()  # Ukrywa główne okno
    input_folder = filedialog.askdirectory(
        title="Wybierz folder zawierający CVE/, domeny.txt oraz nuclei_grouped.txt lub nuclei_scan.txt"
    )
    if not input_folder:
        print("❌ Nie wybrano folderu. Kończę.")
        sys.exit(1)

    input_folder = os.path.expanduser(input_folder)
    if not os.path.isdir(input_folder):
        print("❌ Nieprawidłowa ścieżka folderu wejściowego.")
        sys.exit(1)

    # --- Wyznaczenie plików i folderów w folderze wejściowym ---
    cves_folder = os.path.join(input_folder, "CVE")
    list_of_roots = os.path.join(input_folder, "domeny.txt")
    nuclei_grouped = os.path.join(input_folder, "nuclei_grouped.txt")
    nuclei_scan = os.path.join(input_folder, "nuclei_scan.txt")
    ip_mapping = os.path.join(input_folder, "ip_mapping.txt")

    # --- Sprawdzenie obecności wymaganych plików/folderów ---
    if not os.path.isdir(cves_folder):
        print(f"❌ Brak folderu CVE w {input_folder}")
        sys.exit(1)

    if not os.path.isfile(list_of_roots):
        print(f"❌ Brak pliku domeny.txt w {input_folder}")
        sys.exit(1)

    # Musi istnieć albo nuclei_grouped.txt, albo nuclei_scan.txt
    if not os.path.isfile(nuclei_grouped) and not os.path.isfile(nuclei_scan):
        print(
            f"❌ Brak zarówno pliku nuclei_grouped.txt, jak i nuclei_scan.txt w {input_folder}"
        )
        sys.exit(1)

    # --- Folder, w którym znajduje się ten skrypt (tu są też pozostałe skrypty) ---
    scripts_folder = os.path.dirname(os.path.abspath(__file__))

    # --- Krok 1: nuclei_parser_merged.py ---
    # Jeśli nuclei_grouped.txt już istnieje, pomijamy parser.
    if os.path.isfile(nuclei_grouped):
        print(f"ℹ️ Wykryto istniejący plik nuclei_grouped.txt: {nuclei_grouped}")
        print("⏭️ Pomijam krok parsowania nuclei_scan.txt i przechodzę dalej.\n")
    else:
        nuclei_parser = os.path.join(scripts_folder, "nuclei_parser_merged_improved.py")
        if not os.path.isfile(nuclei_parser):
            print(f"❌ Brak skryptu {nuclei_parser}")
            sys.exit(1)

        if not os.path.isfile(nuclei_scan):
            print(
                f"❌ Nie znaleziono nuclei_grouped.txt, a także brak nuclei_scan.txt w {input_folder}"
            )
            sys.exit(1)

        print(f"ℹ️ Nie znaleziono nuclei_grouped.txt. Będę generować go z nuclei_scan.txt.")

        # Jeśli parser wymaga ip_mapping.txt, użyj wariantu 2-argumentowego.
        # W przeciwnym razie uruchom parser tylko z nuclei_scan.txt.
        if os.path.isfile(ip_mapping):
            run_script(nuclei_parser, nuclei_scan, ip_mapping)
        else:
            run_script(nuclei_parser, nuclei_scan)

        # Po parsowaniu upewnij się, że nuclei_grouped.txt został wygenerowany
        if not os.path.isfile(nuclei_grouped):
            print(
                f"❌ Po uruchomieniu parsera nadal brak pliku nuclei_grouped.txt w {input_folder}"
            )
            sys.exit(1)

    # --- Krok 2: raport_parser_merged.py ---
    raport_parser = os.path.join(scripts_folder, "raport_parser_merged.py")
    if not os.path.isfile(raport_parser):
        print(f"❌ Brak skryptu {raport_parser}")
        sys.exit(1)

    run_script(raport_parser, nuclei_grouped, list_of_roots, cves_folder)

    # --- Krok 3: CVSS_parser_merged.py ---
    cvss_parser = os.path.join(scripts_folder, "CVSS_parser_merged.py")
    sparsowane_folder = os.path.join(input_folder, "sparsowane_raporty")
    os.makedirs(sparsowane_folder, exist_ok=True)

    if not os.path.isfile(cvss_parser):
        print(f"❌ Brak skryptu {cvss_parser}")
        sys.exit(1)

    run_script(cvss_parser, sparsowane_folder)

    # --- Krok 4: html_raport_parser_merged.py ---
    html_parser = os.path.join(scripts_folder, "html_raport_parser_merged.py")
    if not os.path.isfile(html_parser):
        print(f"❌ Brak skryptu {html_parser}")
        sys.exit(1)

    run_script(html_parser, sparsowane_folder)

    # --- Krok 5: Uruchom sed w folderze html_reports ---
    html_reports_folder = os.path.join(sparsowane_folder, "html_reports")
    run_sed_in_html_reports(html_reports_folder)

    print("\n🎉 Wszystkie kroki zakończone pomyślnie!")
    print(f"📄 Finalne raporty znajdują się w: {html_reports_folder}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
raport_parser_subdomains_with_cve.py

Użycie:
    python3 raport_parser_subdomains_with_cve.py <nuclei_grouped.txt> <lista_domen.txt> <cve_folder_or_->

Kompatybilne z nuclei_parser_merged.py (nuclei_grouped.txt):
- Obsługuje nagłówki:
    === Root domain: <root> ===
    === IP range: <cidr> ===
- Obsługuje host-linie:
    <ip> (<host>):

Dodatkowo:
- Generuje raporty dla IP range (CIDR), jeśli występują w nuclei_grouped.txt
- Próbuje mapować CVE HTML (jeśli nazwa pliku to IPv4) do najlepiej pasującego CIDR z nuclei_grouped.txt
- Zachowuje logikę __unmapped__ dla CVE, których nie da się przypisać
"""

from __future__ import annotations

import sys
import os
import re
import ipaddress
from collections import defaultdict, OrderedDict
from typing import List, Dict, Optional, Any, Tuple
from bs4 import BeautifulSoup

ENC = "utf-8"

SERVICE_RECOMMENDATIONS = {
    "ftp": "FTP -> Zalecamy korzystanie z FTPS na porcie 990 i wylaczenie FTP na porcie 21 (jesli mozliwe). Brak zmiany moze prowadzic do podsluchania hasel w plaintext, nieautoryzowanego dostepu do plikow oraz modyfikacji danych przez atakujacych.",
    "postgresql": "PostgreSQL -> Zalecamy aktualizację serwera PostgreSQL do najnowszej wersji, wymuszenie szyfrowania połączeń (TLS), stosowanie silnych haseł i uwierzytelniania kluczami, ograniczenie dostępu sieciowego poprzez firewall/ACL oraz precyzyjne ustawienie reguł w pg_hba.conf (unikać 'trust'). Dodatkowo zalecamy ograniczenie uprawnień superużytkowników, regularne tworzenie zaszyfrowanych kopii zapasowych, monitorowanie logów dostępu oraz szybką instalację poprawek bezpieczeństwa. Brak tych działań może prowadzić do nieautoryzowanego dostępu, modyfikacji lub wycieku danych oraz eskalacji uprawnień.",
    "ssh": "SSH -> Zalecamy aktualizacje SSH, wylaczenie logowania haslem (uzyj kluczy) i ograniczenie dostepu wg adresow IP. Brak zmiany moze prowadzic do brute-force, przejecia konta i nieautoryzowanego dostepu do serwera.",
    "telnet": "Telnet -> Zalecamy wylaczenie, nigdy nie uzywaj hasel w plaintext, zastap SSH. Brak zmiany umozliwia podsluchiwanie hasel i przejecie kontroli nad systemem.",
    "smtp": "SMTP -> Zalecamy aktualizacje serwera, wylaczenie open relay, wlaczenie TLS, konfiguracje SPF/DKIM/DMARC i ograniczenie dostepu do sieci wewnetrznej. Brak zmiany moze prowadzic do wysylania spamu, spoofingu i wycieku poczty.",
    "pop3": "POP3 -> Zalecamy wylaczenie i preferowanie IMAP przez SSL/TLS. Brak zmiany umozliwia podsluchiwanie hasel i kradziez wiadomosci e-mail.",
    "imap": "IMAP -> Zalecamy korzystanie tylko z IMAPS na porcie 993 i wylaczenie IMAP na porcie 143 (jesli mozliwe). Brak zmiany umozliwia podsluch komunikacji i wyciek tresci poczty.",
    "http": "HTTP -> Zalecamy wdrozenie HTTPS (TLS), aktualizacje serwera WWW i sprawdzenie naglowkow bezpieczenstwa. Brak zmiany umozliwia MITM, podsluchiwanie i manipulacje danymi.",
    "https": "HTTPS -> Zalecamy upewnienie sie, ze TLS jest poprawnie skonfigurowany i aktualny. Brak zmiany pozwala na wykorzystanie znanych podatnosci TLS i ataki MITM.",
    "mysql": "MySQL -> Zalecamy sprawdzenie konfiguracji, uzywanie silnych hasel i ograniczenie dostepu do sieci wewnetrznej. Brak zmiany moze prowadzic do nieautoryzowanego dostepu, modyfikacji i wycieku danych.",
    "mongodb": "MongoDB -> Zalecamy wlaczenie uwierzytelniania, TLS, ograniczenie dostepu do zaufanych IP i aktualizacje serwera. Brak zmiany moze prowadzic do wycieku danych i przejecie serwera bazy.",
    "redis": "Redis -> Zalecamy nie wystawiac publicznie, wymusic uwierzytelnianie i TLS, ograniczyc dostep do IP. Brak zmiany umozliwia modyfikacje danych, przejecie systemu lub DDoS.",
    "memcached": "Memcached -> Zalecamy nie wystawiac publicznie, ograniczyc do localhost, stosowac firewall. Brak zmiany umozliwia wycieki danych z pamieci podrecznej i ataki DDoS.",
    "elasticsearch": "Elasticsearch -> Zalecamy nie wystawiac publicznie, wlaczyc uwierzytelnianie i TLS, ograniczyc IP i aktualizowac serwer. Brak zmiany umozliwia dostep do pelnych danych i wycieki wrazliwych informacji.",
    "docker": "Docker -> Zalecamy nie wystawiac demona Dockera publicznie, stosowac TLS i ograniczyc dostep do zaufanych uzytkownikow. Brak zmiany umozliwia przejecie kontenerow i eskalacje uprawnien.",
    "kubernetes-api": "Kubernetes API -> Zalecamy ograniczenie dostepu do API, wlaczenie uwierzytelniania i RBAC, stosowanie TLS. Brak zmiany umozliwia przejecie klastrow, eskalacje uprawnien i manipulacje uslugami.",
    "vpn": "VPN -> Zalecamy upewnienie sie, ze VPN jest aktualny, stosowanie silnego uwierzytelniania i szyfrowania. Brak zmiany moze prowadzic do podsluchu i nieautoryzowanego dostepu do sieci wewnetrznej.",
    "nagios": "Nagios -> Zalecamy ograniczenie dostepu do interfejsu webowego, stosowanie uwierzytelniania i TLS. Brak zmiany umozliwia wyciek danych monitoringu i przejecie kontroli nad systemem.",
    "jenkins": "Jenkins -> Zalecamy aktualizacje, wymuszenie HTTPS, ograniczenie dostepu do sieci wewnetrznej i uwierzytelnianie. Brak zmiany umozliwia RCE, kradziez konfiguracji i przejecie projektow.",
    "vnc": "VNC -> Zalecamy nie wystawiac publicznie, wymuszenie silnych hasel i uwierzytelniania TLS, ograniczenie dostepu do IP. Brak zmiany umozliwia przejecie pulpitu i danych uzytkownika.",
    "teamviewer": "TeamViewer -> Zalecamy uzywanie tylko zaufanych urzadzen i kont oraz wlaczenie uwierzytelniania dwuskladnikowego. Brak zmiany umozliwia zdalny dostep nieautoryzowany.",
    "cassandra": "Cassandra -> Zalecamy ograniczenie dostepu do portow, stosowanie uwierzytelniania i szyfrowania TLS. Brak zmiany umozliwia wyciek danych i nieautoryzowana manipulacje klastrami.",
    "rabbitmq": "RabbitMQ -> Zalecamy stosowanie TLS, uwierzytelniania, ograniczenie dostepu do IP i aktualizacje serwera. Brak zmiany moze prowadzic do podsluchu wiadomosci, przejecie kolejek i eskalacji uprawnien.",
    "jira": "Jira -> Zalecamy aktualizacje aplikacji, wymuszenie HTTPS, stosowanie silnych hasel i ograniczenie dostepu do sieci wewnetrznej. Brak zmiany moze prowadzic do wycieku danych projektowych i atakow RCE.",
    "gitlab": "GitLab -> Zalecamy aktualizacje do najnowszej wersji, wymuszenie HTTPS, stosowanie MFA i silnych hasel. Brak zmiany umozliwia wyciek repozytoriow, RCE i przejecie kont uzytkownikow.",
    "docker-registry": "Docker Registry -> Zalecamy wymuszenie TLS, uwierzytelniania i ograniczenie dostepu do zaufanych hostow. Brak zmiany umozliwia przejecie obrazow i wstrzykniecie zlosliwego kodu.",
    "kibana": "Kibana -> Zalecamy nie wystawiac publicznie, wlaczenie uwierzytelniania i TLS, ograniczenie dostepu do IP. Brak zmiany umozliwia dostep do danych Elasticsearch i ich manipulacje.",
    "prometheus": "Prometheus -> Zalecamy nie wystawiac publicznie, stosowanie uwierzytelniania i ograniczenie dostepu do sieci wewnetrznej. Brak zmiany umozliwia podsluch danych monitoringu i ataki na systemy.",
    "grafana": "Grafana -> Zalecamy aktualizacje do najnowszej wersji, wymuszenie HTTPS, stosowanie silnych hasel i MFA. Brak zmiany umozliwia przejecie paneli, wyciek danych i manipulacje alertami.",
    "ftp-alt": "FTP-alt -> Zalecamy uzywanie tylko FTPS/SFTP, wylaczenie FTP na porcie 21 i ograniczenie dostepu do zaufanych hostow. Brak zmiany umozliwia podsluch i nieautoryzowany dostep do plikow.",
    "sip": "SIP -> Zalecamy stosowanie TLS, uwierzytelniania i ograniczenie dostepu do IP oraz monitorowanie logow. Brak zmiany umozliwia podsluch rozmow i ataki DoS.",
    "nfs": "NFS -> Zalecamy ograniczenie dostepu do zaufanych hostow, stosowanie eksportow read-only i aktualizacje serwera. Brak zmiany umozliwia nieautoryzowany dostep do plikow i modyfikacje danych.",
    "tftp": "TFTP -> Zalecamy nie wystawiac publicznie, uzywanie tylko w sieci wewnetrznej i monitorowanie logow. Brak zmiany umozliwia wyciek plikow i modyfikacje firmware.",
    "rsync": "Rsync -> Zalecamy stosowanie TLS/SSH, ograniczenie dostepu do IP i wymuszenie uwierzytelniania. Brak zmiany umozliwia nieautoryzowany transfer plikow.",
    "rpcbind": "RPCBind -> Zalecamy wylaczenie jesli zbedne, ograniczenie dostepu do sieci wewnetrznej i aktualizacje serwera. Brak zmiany umozliwia ataki DoS i wyciek danych.",
    "snmp": "SNMP -> Zalecamy uzywanie tylko SNMPv3, zmiane community strings, ograniczenie dostepu do IP i wylaczenie jesli zbedne. Brak zmiany umozliwia podsluch i manipulacje urzadzeniami.",
    "smb": "SMB -> Zalecamy wylaczenie SMBv1, ograniczenie do sieci wewnetrznej, stosowanie silnych hasel i aktualizacje systemow. Brak zmiany umozliwia ransomware, wycieki plikow i ataki lateralne.",
    "rdp": "RDP -> Zalecamy aktualizacje serwera, wymaganie VPN/IP whitelist, wlaczenie MFA i silnych hasel, rozwazenie RDP Gateway. Brak zmiany umozliwia przejecie sesji i systemu.",
    "dns": "DNS -> Zalecamy upewnienie sie, ze serwer DNS jest zaktualizowany, ograniczenie transferu stref, wdrozenie DNSSEC i monitorowanie logow. Brak zmiany umozliwia DNS spoofing i podszywanie sie pod domeny.",
    "ldap": "LDAP -> Zalecamy uzywanie LDAPS (port 636), uwierzytelnianie i ograniczenie dostepu do zaufanych hostow. Brak zmiany umozliwia podsluch hasel i manipulacje katalogami.",
    "h323": "H323 -> Zalecamy stosowanie TLS, ograniczenie dostepu do IP i monitorowanie logow. Brak zmiany umozliwia podsluch i manipulacje sygnalem glosowym.",
    "sip-tls": "SIP-TLS -> Zalecamy wlaczenie TLS, uwierzytelniania i ograniczenie dostepu do IP. Brak zmiany umozliwia podsluch i manipulacje polaczeniami VoIP.",
    "ldap-slapd": "LDAP-Slapd -> Zalecamy aktualizacje serwera, stosowanie uwierzytelniania i ograniczenie dostepu do IP. Brak zmiany moze prowadzic do wyciek hasel i nieautoryzowana modyfikacje katalogow.",
    "mssql": "MSSQL -> Zalecamy stosowanie uwierzytelniania, TLS i ograniczenie dostepu do zaufanych hostow. Brak zmiany umozliwia wyciek danych i nieautoryzowany dostep.",
    "oracle-db": "Oracle DB -> Zalecamy aktualizacje bazy, stosowanie TLS, ograniczenie dostepu do IP i uzywanie silnych hasel. Brak zmiany umozliwia wyciek danych i przejecie serwera.",
    "hadoop": "Hadoop -> Zalecamy ograniczenie dostepu, stosowanie uwierzytelniania i TLS oraz aktualizacje klastrow. Brak zmiany umozliwia wyciek danych i manipulacje obliczeniami w klastrze.",
    "couchdb": "CouchDB -> Zalecamy nie wystawiac publicznie, wlaczenie uwierzytelniania i TLS, ograniczenie dostepu do IP. Brak zmiany umozliwia wyciek dokumentow i przejecie bazy.",
    "rabbitmq-management": "RabbitMQ Management -> Zalecamy wlaczenie HTTPS, uwierzytelniania i ograniczenie dostepu do IP. Brak zmiany umozliwia podsluch i manipulacje kolejkami.",
    "splunk": "Splunk -> Zalecamy aktualizacje, wymuszenie HTTPS, stosowanie uwierzytelniania i ograniczenie dostepu do sieci wewnetrznej. Brak zmiany umozliwia wyciek logow i nieautoryzowany dostep.",
    "consul": "Consul -> Zalecamy nie wystawiac publicznie, wlaczenie TLS i ACL, ograniczenie dostepu do IP. Brak zmiany umozliwia manipulacje uslugami i wyciek danych konfiguracyjnych.",
    "vault": "Vault -> Zalecamy wymuszenie TLS, uwierzytelniania i ograniczenie dostepu do zaufanych hostow. Brak zmiany umozliwia wyciek sekretow i przejecie dostepu do systemow.",
    "exim": "Exim -> Zalecamy aktualizacje do najnowszej wersji, stosowanie szyfrowania TLS, wymuszenie silnych hasel i ograniczenie dostepu do zaufanych hostow. Brak zmiany umozliwia podsluch poczty i wysylanie spamu.",
    "svnserve": "SVNServe -> Zalecamy aktualizacje do najnowszej wersji, wymuszenie polaczen szyfrowanych (TLS), stosowanie silnych hasel i ograniczenie dostepu do zaufanych uzytkownikow. Brak zmiany umozliwia wyciek kodu zrodlowego i nieautoryzowana zmiana repozytorium.",
    "nodejs": "Node.js -> Zalecamy aktualizacje zaleznosci, uruchamianie za reverse-proxy (np. Nginx) z TLS, oraz ograniczenie ekspozycji portow publicznych. Brak zmiany umozliwa ataki RCE, wyciek danych i manipulacje aplikacja.",
    "unknown": "Nierozpoznany serwis -> Zalecamy sprawdzenie co dziala na tym porcie, a jesli nie jest potrzebny – wylaczenie uslugi. Brak zmiany moze prowadzic do nieznanych wektorow ataku."
}

HEADER_DESCRIPTIONS = OrderedDict([
    ("clear-site-data", "Czyszczenie danych po wylogowaniu"),
    ("content-security-policy", "Zapobieganie atakom XSS"),
    ("cross-origin-embedder-policy", "Izolacja zasobow cross-origin"),
    ("cross-origin-opener-policy", "Izolacja okien i procesow"),
    ("cross-origin-resource-policy", "Ochrona zasobow przed cross-origin"),
    ("permissions-policy", "Kontrola dostepu do funkcji przegladarki"),
    ("referrer-policy", "Kontrola jakie informacje o zrodle (refererze) sa przesylane"),
    ("strict-transport-security", "Wymuszanie HTTPS przez przegladarke (HSTS)"),
    ("x-content-type-options", "Zapobieganie atakom MIME sniffing"),
    ("x-frame-options", "Ochrona przed clickjacking"),
    ("x-permitted-cross-domain-policies", "Ograniczenie polityk cross-domain"),
    ("expect-ct", "Wymuszanie Certificate Transparency dla TLS"),
    ("feature-policy", "Kontrola dostepu do funkcji przegladarki (starsza wersja Permissions-Policy)"),
    ("report-to", "Konfiguracja endpointow do raportowania naruszen bezpieczenstwa"),
    ("nel", "Network Error Logging – raportowanie bledow sieciowych"),
    ("x-xss-protection", "Wlaczenie podstawowej ochrony przed XSS w przegladarkach (starsze)"),
    ("upgrade-insecure-requests", "Automatyczne przekierowanie zasobow HTTP do HTTPS"),
    ("cross-origin-resource-sharing", "CORS – kontrola dostepu do zasobow cross-origin"),
    ("timing-allow-origin", "Kontrola timing attacks przy zasobach cross-origin"),
    ("set-cookie HttpOnly; Secure; SameSite", "Bezpieczna konfiguracja ciasteczek"),
    ("cache-control", "Kontrola pamieci podrecznej wrazliwych danych"),
])

EXAMPLE_DOMAINS_RE = re.compile(r'\b(?:example\.com|example\.org|example\.net)\b', re.I)

def is_example_entry(entry: Dict[str, Any]) -> bool:
    if not entry:
        return False
    host = (entry.get('host') or "") or ""
    services = (entry.get('services') or "") or ""
    ip = (entry.get('ip') or "") or ""
    combined = " ".join([str(host), str(services), str(ip)])
    return bool(EXAMPLE_DOMAINS_RE.search(combined))

URL_RE = re.compile(r'(https?://[^\s\[\]"]+)', re.I)
FQDN_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b', re.I)
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
B64ISH_RE = re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$')

def is_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s.strip()), ipaddress.IPv4Address)
    except Exception:
        return False

def sanitize_filename(name: str) -> str:
    # "10.0.0.0/24" -> "10.0.0.0_24"
    name = name.strip().replace("/", "_")
    name = re.sub(r'[^a-zA-Z0-9._-]+', "_", name)
    name = re.sub(r'_+', "_", name).strip("_")
    return name or "report"

def extract_domain_from_line(ln: str) -> Optional[str]:
    if not ln:
        return None
    m = URL_RE.search(ln)
    if m:
        return m.group(1)
    dm = FQDN_RE.search(ln)
    if dm:
        return dm.group(0)
    ipm = IPV4_RE.search(ln)
    if ipm:
        return ipm.group(0)
    return None

def extract_resource_from_line(ln: str):
    if not ln:
        return None
    m = URL_RE.search(ln)
    if m:
        return m.group(1)
    m = re.search(r'([a-z0-9\.-]+\.[a-z]{2,}[^\s\[\]"]*/[^\s\[\]"]+)', ln, re.I)
    if m:
        cand = m.group(1).strip()
        if not B64ISH_RE.match(cand):
            return cand
    dm = FQDN_RE.search(ln)
    if dm:
        cand = dm.group(0).strip()
        if not B64ISH_RE.match(cand):
            return cand
    return None

def split_artifact_msg(msg: Optional[str]) -> Tuple[str, Optional[str]]:
    if not msg:
        return ("", None)
    parts = msg.split("->", 1)
    title = parts[0].strip()
    rec = parts[1].strip() if len(parts) > 1 else None
    return (title, rec)

def safe_read(path: str) -> str:
    with open(path, 'r', encoding=ENC, errors='replace') as f:
        return f.read()

def clean_ansi(s: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[mK]', '', s)

def unique_preserve(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def format_nuclei_cve_finding(line: str) -> str:
    """
    Convert a Nuclei CVE result to the report format expected by CVSS_parser_merged.py.

    Example:
        [CVE-2023-5561] [http] [medium] https://host/path [route="wp-json/..."]

    becomes:
        CVE-2023-5561 https://host/path [route="wp-json/..."]

    Only the leading Nuclei metadata brackets directly following the CVE are
    removed. Evidence brackets appearing later in the line (for example
    [route=...], [matched-at=...], etc.) are preserved verbatim.
    """
    raw = (line or "").strip()
    if not raw:
        return raw

    # Most common Nuclei form: [CVE-YYYY-NNNN] [protocol] [severity] evidence...
    m = re.match(r'^\[(CVE-\d{4}-\d{4,7})\](.*)$', raw, re.I)
    if m:
        cve = m.group(1).upper()
        rest = m.group(2).lstrip()
    else:
        # Also accept a CVE already written without brackets. This keeps the
        # function idempotent and lets older grouped files pass through safely.
        m = re.match(r'^(CVE-\d{4}-\d{4,7})\b(.*)$', raw, re.I)
        if not m:
            return raw
        cve = m.group(1).upper()
        rest = m.group(2).lstrip()

    # Strip only consecutive metadata tokens at the START of the remaining
    # text. Once real evidence begins (URL/path/text), all later brackets are
    # left untouched. This intentionally preserves e.g. [route="..."].
    while rest.startswith('['):
        token = re.match(r'^\[([^]\r\n]+)\]\s*', rest)
        if not token:
            break

        value = token.group(1).strip()
        value_l = value.lower()

        # Nuclei protocol/severity/template metadata commonly placed directly
        # after the template/CVE id. Do not consume evidence-style key=value
        # tokens, because those are useful in the report.
        is_evidence = '=' in value or value_l.startswith(('route:', 'matched-at:', 'matcher-name:'))
        if is_evidence:
            break

        rest = rest[token.end():].lstrip()

    return f"{cve} {rest}".rstrip() if rest else cve

NOISE_PATTERNS = re.compile(r'(mx-fingerprint|nameserver|spf-record)', re.I)
PROXY_NOISE_PATTERNS = re.compile(
    r'(RewriteEngine|RewriteRule|ProxyPassMatch|ProxyPassReverse|ProxyPass|mod_proxy|re-inserted into the proxied request-target)',
    re.I
)

DETECT_TAG_RE = re.compile(r'\[([a-z0-9\-\_]+-detect)(?::([0-9]{1,5}))?(?::[^\]]+)?\]', re.I)
MISSING_HDR_RE = re.compile(r'\[http-missing-security-headers:([a-z0-9\-\s;]+)\]', re.I)

SERVICE_NAME_MAP = {
    'ftp-detect': 'ftp',
    'ssh-detect': 'ssh',
    'http-detect': 'http',
    'https-detect': 'https',
    'mysql-detect': 'mysql',
    'mariadb-detect': 'mysql',
    'postgres-detect': 'postgresql',
    'postgresql-detect': 'postgresql',
    'pgsql-detect': 'postgresql',
    'rdp-detect': 'rdp',
    'smb-detect': 'smb',
    'mongodb-detect': 'mongodb',
    'redis-detect': 'redis',
    'elasticsearch-detect': 'elasticsearch',
    'jenkins-detect': 'jenkins',
    'kubernetes-api-detect': 'kubernetes-api',
    'docker-detect': 'docker',
    'vnc-detect': 'vnc',
    'smtp-detect': 'smtp',
}

def normalize_service_tag(tag: str, raw_lines: List[str]) -> str:
    t = (tag or "").lower().strip()
    if t in SERVICE_NAME_MAP:
        return SERVICE_NAME_MAP[t]
    if t.endswith('-detect'):
        base = t[:-7]
        if base in ('pg', 'pgsql', 'postgres', 'postgresql'):
            return 'postgresql'
        if base in ('mariadb',):
            return 'mysql'
        if base:
            return base
    if raw_lines:
        first = raw_lines[0]
        return first if len(first) <= 120 else (first[:117] + '...')
    return tag

def extract_port_from_line(line: str, tag: Optional[str] = None) -> Optional[str]:
    m = re.search(r'\[?[^\]]*[:\s]([0-9]{2,5})\]?', line)
    if m:
        port = m.group(1)
        if 1 <= int(port) <= 65535:
            return port
    m = re.search(r'port[:\s]+([0-9]{2,5})', line, re.I)
    if m:
        port = m.group(1)
        if 1 <= int(port) <= 65535:
            return port
    m = re.search(r'\b(?:tcp|udp)\/([0-9]{2,5})\b', line, re.I)
    if m:
        port = m.group(1)
        if 1 <= int(port) <= 65535:
            return port
    if tag:
        for tag_match in re.finditer(re.escape(tag), line, re.I):
            tail = line[tag_match.end(): tag_match.end()+40]
            m2 = re.search(r'[:\s\[]*([0-9]{2,5})', tail)
            if m2:
                port = m2.group(1)
                if 1 <= int(port) <= 65535:
                    return port
    m = re.search(r'([a-z0-9\.\-]+):([0-9]{2,5})', line, re.I)
    if m:
        port = m.group(2)
        if 1 <= int(port) <= 65535:
            return port
    m = re.search(r'\b([0-9]{2,5})\b', line)
    if m:
        port = m.group(1)
        if 1 <= int(port) <= 65535:
            return port
    return None

# ---------------- ARTIFACT_PATTERNS ----------------
ARTIFACT_PATTERNS = [
    (
        re.compile(r'^(?!.*CVE-).*?(wp-json[^ \t\n\r]*users|enumeration.*users|wordpress.*enumeration)', re.I),
        "WordPress (enumeracja uzytkownikow) -> zablokowanie mozliwosci enumeracji kont przez URL. Brak tej zmiany umozliwia atakujacemu poznanie kont uzytkownikow, ulatwiajac ataki brute-force lub phishing.",
        lambda ln: (
            (lambda u: u.group(1) if u else None)(re.search(r'(https?://[^\s\[\]"]+)', ln))
            or (lambda p: p.group(1) if p else None)(re.search(r'([a-z0-9\.-]+\.[a-z]{2,}[^\s\[\]"]*/[^\s\[\]"]+)', ln, re.I))
            or None
        )
    ),
    (re.compile(r'^(?!.*CVE-).*?(wp-json.*users|enumeration.*users|wordpress.*enumeration)', re.I),
     "WordPress (enumeracja uzytkownikow) -> zablokowanie mozliwosci enumeracji kont przez URL. "
     "Brak tej zmiany umozliwia atakujacemu poznanie kont uzytkownikow, ulatwiajac ataki brute-force lub phishing.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'wp-user-enum', re.I),
     "WordPress user enumeration -> ograniczyć możliwość odpytywania użytkowników; brak ochrony może umożliwić poznanie loginów użytkowników, co ułatwia późniejsze próby logowania i ataki brute-force.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'\[ftp-anonymous-login\]', re.I),
     "FTP (anonymous login) -> natychmiastowe wylaczenie logowania anonimowego. Brak zmiany moze prowadzic do wycieku poufnych danych, modyfikacji plikow lub umieszczenia zlosliwego oprogramowania.",
     None),
    (re.compile(r'\[deprecated-tls:tls_1\.[01]\]', re.I),
     "Przestarzala wersja protokolu TLS (1.0/1.1) -> zmiane protokolu szyfrujacego TLS na wersje 1.2 lub 1.3. Brak aktualizacji moze umozliwic podsluchiwanie komunikacji, modyfikacje danych (MITM) oraz wykorzystanie znanych podatnosci kryptograficznych.",
     None),
    (re.compile(r'\[untrusted-root-certificate\]', re.I),
     "Certyfikat niepodpisany przez zaufany CA -> sprawdzenie certyfikatu SSL i pelnego lancucha certyfikatow. Brak zmiany moze prowadzic do atakow typu MITM i podsluchiwania komunikacji.",
     None),
    (re.compile(r'\[litespeed-cache\].*CVE-\d{4}-\d{4,7}', re.I),
     "LiteSpeed (CVE) -> aktualizacje LiteSpeed Cache do najnowszej wersji. Brak aktualizacji moze umozliwic zdalne wykonanie kodu lub wyciek danych.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'(?:AIza[0-9A-Za-z_\-]{35})', re.I),
     "Google API Key (jawny klucz Google API) -> ujawnienie klucza API może pozwolić na nieautoryzowane korzystanie z usług Google (Billing, Maps, YouTube, Cloud APIs). Zalecane: rotacja klucza, ustawienie ograniczeń (referer/IP/app) oraz usunięcie klucza z repozytoriów/publicznych plików konfiguracyjnych.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'manifests.*joomla|joomla.*manifest', re.I),
     "Joomla (dostepny manifest) -> zablokowanie dostepu do plikow .xml. Manifest moze ujawniac wersje CMS i wrazliwe sciezki, co ulatwia ataki typu reconnaissance.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'robots\.txt', re.I),
     "Widoczny zasob robots.txt -> nie ujawniac poufnych sciezek. Brak zmiany umozliwia atakujacym odnalezienie wrazliwych katalogow i plikow.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'quizmaker.*CVE-\d{4}-\d{4,7}', re.I),
     "WordPress QuizMaker (CVE) -> natychmiastowa aktualizacje wtyczki Quiz Maker. Niezalatana wtyczka moze prowadzic do RCE lub eskalacji uprawnien.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'same-?site|same site|same_site', re.I),
     "Brak ustawienia ciasteczka SameSite -> wlaczenie SameSite=Strict. Brak zmiany umozliwia ataki typu CSRF.",
     lambda ln: extract_domain_from_line(ln)),
    (re.compile(r'\[phpmyadmin\]', re.I),
     "Dostepny PhpMyAdmin -> ograniczenie dostepu tylko do zaufanych IP i wymuszenie uwierzytelniania. Brak zmiany umozliwia atak brute-force i przejecie baz danych.",
     None),
    (re.compile(r'\[admin-login\]', re.I),
     "Widoczny panel admina -> ograniczenie dostepu do sieci wewnetrznej lub przez VPN. Brak zmiany umozliwia nieautoryzowany dostep do systemu.",
     None),
    (re.compile(r'phpunit|phpunit\.phar', re.I),
     "Wykryto PhpUnit -> natychmiastowe usuniecie plikow testowych z serwera produkcyjnego. Brak zmiany umozliwia RCE.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'debug\.env', re.I),
     "Plik .env dostepny publicznie -> usuniecie pliku i zabezpieczenie serwera. Brak zmiany moze prowadzic do wycieku hasel i kluczy API.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'config\.bak|backup', re.I),
     "Pliki backupu lub konfiguracji dostepne publicznie -> ich usuniecie lub ograniczenie dostepu. Brak zmiany ulatwia atakujacym dostep do poufnych danych.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'sql error|database error', re.I),
     "Wyciek informacji o bazie danych -> weryfikacje obslugi bledow i filtracje inputow. Brak zmiany moze umozliwic SQLi.",
     None),
    (re.compile(r'wp-login\.php', re.I),
     "WordPress login -> ograniczenie prob logowania i wymuszenie MFA. Brak zmiany ulatwia brute-force i przejecie kont.",
     None),
    (re.compile(r'\.git', re.I),
     "Repozytorium Git dostepne publicznie -> jego usuniecie lub ograniczenie dostepu. Brak zmiany umozliwia poznanie kodu zrodlowego i konfiguracji.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'xmlrpc\.php', re.I),
     "WordPress xmlrpc -> wylaczenie, jesli nieuzywane. Brak zmiany umozliwia ataki brute-force i DDoS.",
     None),
    (re.compile(r'open-redirect', re.I),
     "Wykryto podatnosc open redirect -> weryfikacje parametrow URL i wprowadzenie walidacji. Brak zmiany umozliwia phishing i przekierowania na zlosliwe strony.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'adminer', re.I),
     "Dostepny Adminer -> ograniczenie dostepu do zaufanych IP i wymuszenie uwierzytelniania. Brak zmiany umozliwia przejecie bazy danych i RCE.",
     None),
    (re.compile(r'phpinfo', re.I),
     "Wykryto phpinfo() -> usuniecie lub ograniczenie dostepu. Brak zmiany ujawnia konfiguracje serwera i wersje oprogramowania, ulatwiajac ataki.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'sqlmap', re.I),
     "Wykryto slady SQLmap -> monitorowanie atakow i zabezpieczenie inputow. Brak zmiany umozliwia SQLi i wyciek danych.",
     lambda ln: extract_resource_from_line(ln)),
    (re.compile(r'wp-content/plugins', re.I),
     "WordPress plugin -> aktualizacje wtyczek do najnowszych wersji. Brak aktualizacji umozliwia RCE lub inne krytyczne podatnosci.",
     lambda ln: extract_resource_from_line(ln)),
]

# ------------------ parse nuclei_grouped.txt ------------------
def parse_nuclei_blocks(content: str) -> Dict[str, Dict[str, Any]]:
    """
    Zwraca mapę:
      key = root_label (domain albo CIDR)
      val = {
         'root_type': 'domain'|'iprange',
         'raw_block': ...,
         'hosts': OrderedDict(host -> {ip, raw_findings, services, cves, missing_headers})
      }
    """
    res: Dict[str, Dict[str, Any]] = OrderedDict()
    if not content:
        return res

    content = clean_ansi(content)

    root_any_re = re.compile(
        r'^===\s*(?P<kind>Root\s+domain|IP\s+range)\s*:\s*(?P<root>[^\s=]+)\s*===\s*$',
        re.I | re.M
    )
    host_header_re = re.compile(
        r'^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s*\((?P<host>[^)]+)\):\s*$',
        re.M
    )

    roots = list(root_any_re.finditer(content))
    if not roots:
        return res

    for idx, m in enumerate(roots):
        kind = (m.group('kind') or '').lower()
        root = (m.group('root') or '').strip().lower()
        root_type = 'iprange' if 'ip' in kind else 'domain'

        start = m.end()
        end = roots[idx + 1].start() if idx + 1 < len(roots) else len(content)
        block = content[start:end]

        hosts: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        host_headers = list(host_header_re.finditer(block))

        for j, hh in enumerate(host_headers):
            ip = (hh.group('ip') or '').strip()
            host = (hh.group('host') or '').strip().lower()

            start_h = hh.end()
            end_h = host_headers[j + 1].start() if j + 1 < len(host_headers) else len(block)
            host_block = block[start_h:end_h]

            raw_findings: List[str] = []
            services: Dict[str, Dict[str, Any]] = {}
            cves = set()
            missing_headers = set()

            for ln in host_block.splitlines():
                ln = ln.rstrip()
                if not ln.strip():
                    continue
                if NOISE_PATTERNS.search(ln) or PROXY_NOISE_PATTERNS.search(ln):
                    continue
                raw = ln.strip()
                raw_findings.append(raw)

                mh = MISSING_HDR_RE.search(ln)
                if mh:
                    hdrs_raw = mh.group(1)
                    for part in re.split(r'[,\s;]+', hdrs_raw):
                        p = part.strip()
                        if p:
                            missing_headers.add(p.lower())
                    continue

                d = DETECT_TAG_RE.search(ln)
                if d:
                    tag = d.group(1).lower()
                    port_in_bracket = d.group(2)
                    services.setdefault(tag, {'raw_lines': [], 'port': None})
                    if raw not in services[tag]['raw_lines']:
                        services[tag]['raw_lines'].append(raw)
                    if port_in_bracket and not services[tag].get('port'):
                        services[tag]['port'] = port_in_bracket
                    else:
                        found_port = extract_port_from_line(ln, tag=tag)
                        if found_port and not services[tag].get('port'):
                            services[tag]['port'] = found_port

                for cv in re.findall(r'\b(CVE-\d{4}-\d{4,7})\b', ln, re.I):
                    cves.add(cv.upper())

            hosts[host] = {
                'ip': ip,
                'raw_findings': raw_findings,
                'services': services,
                'cves': sorted(list(cves)),
                'missing_headers': sorted(list(missing_headers))
            }

        res[root] = {'root_type': root_type, 'raw_block': block, 'hosts': hosts}

    return res

# ------------------ CVE parsing ------------------
def parse_cve_html_file(path: str) -> list:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            html_content = f.read()
    except Exception:
        return []

    soup = BeautifulSoup(html_content, "html.parser")

    for br in soup.find_all("br"):
        br.replace_with("\n")
    for p in soup.find_all("p"):
        p.insert_before("\n\n")
    for li in soup.find_all("li"):
        li.insert_before("\n    ")
    for ul in soup.find_all("ul"):
        ul.insert_before("\n")

    for li in soup.find_all("li"):
        if li.string:
            urls = re.findall(r'https?://[^\s]+', li.string)
            if urls:
                new_content = li.string
                for url in urls:
                    new_content = new_content.replace(url, f'\n{url}')
                li.string.replace_with(new_content)

    text = soup.get_text("\n", strip=True)

    text = re.sub(r'(?m)^(?:[-•\s]*)?(Rekomendacje\s*/\s*uwagi|Raport.*)$', '', text)
    text = re.sub(r'Rekomendacje:\s*\n\s*', r'Rekomendacje: ', text)
    text = re.sub(r'Błąd:\s*\n\s*([A-Za-z0-9\.\-]+:)', r'Błąd: \1', text)
    text = re.sub(r'(?m)^\s*-\s*(Następujące|Wykryto|IP:)', r'\1', text)
    text = re.sub(r'(?m)(?<!\n)(Wykryto|Następujące\s+serwery\s+mają\s+otwarty\s+port\s+bazy\s+danych|IP:)', r'\n\1', text)
    text = re.sub(r'\s*:\s*//', '://', text)
    text = re.sub(r'\s+([,.:;])', r'\1', text)
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)

    lines = [line.strip(" -") for line in text.splitlines()]
    lines = [l for l in lines if l.strip()]

    section5_match = re.search(r'5\.\s*Podatności wykryte na adresie:\s*([a-z0-9\.-]+)', "\n".join(lines), re.I)
    section5_domain = section5_match.group(1).strip() if section5_match else None
    if section5_domain:
        lines = [l for l in lines if l.strip().lower() != section5_domain.lower()]

    zalecenie_line = "Zalecamy przeprowadzić weryfikację, czy podobne problemy występują w innych, publicznie udostępnionych przez Państwa systemach."
    zalecenie_indices = [i for i, l in enumerate(lines) if l.strip() == zalecenie_line]
    if zalecenie_indices:
        last_idx = zalecenie_indices[-1]
        lines = [l for i, l in enumerate(lines) if l.strip() != zalecenie_line or i == last_idx]

    try:
        idx_info = next(i for i, l in enumerate(lines) if l.startswith("Jeżeli któreś z podatności nie dotyczą podmiotu"))
        if lines[idx_info - 1].strip() != zalecenie_line:
            lines.insert(idx_info, zalecenie_line)
    except StopIteration:
        if zalecenie_line not in lines:
            lines.append(zalecenie_line)

    last_three = [
        "Zalecamy przeprowadzić weryfikację, czy podobne problemy występują w innych, publicznie udostępnionych przez Państwa systemach.",
        "Jeżeli któreś z podatności nie dotyczą podmiotu, prosimy o informację zwrotną wraz z wyjaśnieniem. Pozwoli to na przeanalizowanie takiego przypadku przez nas i ewentualne wykluczenie podatności z przyszłych raportów.",
        "Prosimy pamiętać, że skanowanie jest rozłożone w czasie. Tym samym, ze względu na czas trwania procesu, może się okazać, że część problemów opisanych wyżej została już przez Państwa rozwiązana."
    ]
    if len(lines) >= 3 and lines[-3:] == last_three:
        lines = lines[:-3]

    clean_text = "\n".join(lines).strip()
    clean_text = re.sub(r'(?m)^(\s{0,2}http)', r'        \1', clean_text)
    clean_text = re.sub(r'(?m)^(\s{0,2}CVE-\d{4}-\d+)', r'        \1', clean_text)
    clean_text = re.sub(r'\n{3,}', '\n\n', clean_text)

    host_name = os.path.splitext(os.path.basename(path))[0].lower()

    # Metadata used only for reliable assignment of CVE-folder reports to roots.
    # Nothing from the source report is removed because of these fields.
    source_domains = sorted(set(
        d.lower().rstrip(".")
        for d in FQDN_RE.findall(clean_text)
        if d
    ))
    source_ips = sorted(set(IPV4_RE.findall(clean_text)))

    return [{
        "ip": None,
        "host": host_name,
        "services": None,
        "cves": [],
        "recs": [clean_text],
        "source_domains": source_domains,
        "source_ips": source_ips,
        "source_file": os.path.basename(path),
    }]


def _entry_full_text_for_mapping(entry: Dict[str, Any]) -> str:
    """Lossless text used only to decide which root owns a CVE-folder report."""
    parts: List[str] = []
    parts.append(str(entry.get("host") or ""))
    parts.append(str(entry.get("source_file") or ""))
    for value in entry.get("source_domains") or []:
        parts.append(str(value))
    for value in entry.get("source_ips") or []:
        parts.append(str(value))
    for value in entry.get("recs") or []:
        parts.append(str(value))
    return "\n".join(parts)


def _entry_mentions_root(entry: Dict[str, Any], root: str) -> bool:
    """
    True when the report content explicitly references root or one of its subdomains.
    This fixes CVE HTML files whose filename does not contain the scanned domain.
    """
    root = (root or "").strip().lower().rstrip(".")
    if not root:
        return False

    host = (entry.get("host") or "").strip().lower().rstrip(".")
    if host == root or host.endswith("." + root):
        return True

    for domain in entry.get("source_domains") or []:
        d = str(domain).strip().lower().rstrip(".")
        if d == root or d.endswith("." + root):
            return True

    text = _entry_full_text_for_mapping(entry).lower()
    pattern = re.compile(
        r"(?<![a-z0-9.-])(?:[a-z0-9-]+\.)*" + re.escape(root) + r"(?=$|[^a-z0-9.-])",
        re.I,
    )
    return bool(pattern.search(text))


def _dedupe_cve_source_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate identical CVE-folder report payloads without dropping unique findings."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for entry in entries:
        key = (
            (entry.get("host") or "").lower(),
            tuple(entry.get("cves") or []),
            tuple(entry.get("recs") or []),
            tuple(entry.get("source_domains") or []),
            entry.get("source_file") or "",
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(entry)
    return out


# ------------------ CVE helpers ------------------
def normalize_services_str(services_str: Optional[str]) -> Optional[str]:
    if not services_str:
        return services_str
    parts = [p.strip() for p in services_str.split(',') if p.strip()]
    parts = unique_preserve(parts)
    return ", ".join(parts)

def dedupe_cves_list(cves: List[Any]) -> List[Any]:
    if not cves:
        return []
    if isinstance(cves[0], dict):
        seen_ids = set()
        out = []
        for c in cves:
            cid = c.get('id') if isinstance(c, dict) else str(c)
            if cid and cid not in seen_ids:
                seen_ids.add(cid)
                out.append(c)
        return out
    seen = set()
    out = []
    for c in cves:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out

def merge_cve_entries_per_host(entries: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    merged = {}
    for ent in entries:
        host = (ent.get('host') or "").lower()
        if not host:
            host = "__unknown__"
        if host not in merged:
            merged[host] = {'ips': [], 'services_list': [], 'cves': [], 'cve_details': [], 'recs': []}
        m = merged[host]
        ip = ent.get('ip') or ""
        if ip and ip not in m['ips']:
            m['ips'].append(ip)
        sv = ent.get('services')
        if sv:
            parts = [p.strip() for p in sv.split(',') if p.strip()]
            for p in parts:
                if p not in m['services_list']:
                    m['services_list'].append(p)
        for c in (ent.get('cves') or []):
            if c not in m['cves']:
                m['cves'].append(c)
        for detail in (ent.get('cve_details') or []):
            if detail and detail not in m['cve_details']:
                m['cve_details'].append(detail)
        for r in (ent.get('recs') or []):
            if r not in m['recs']:
                m['recs'].append(r)
    for h, val in merged.items():
        val['services'] = ", ".join(val['services_list']) if val['services_list'] else None
        del val['services_list']
    return merged

PGP_ANSI = "\033[1;4;31m"
PGP_RESET = "\033[0m"
PGP_DOMAINS_REGEX: List[str] = []

def should_add_pgp(domain: str) -> bool:
    d = (domain or "").lower().strip()
    for pat in PGP_DOMAINS_REGEX:
        try:
            if re.match(pat, d, re.I):
                return False
        except re.error:
            continue
    return True

# ------------------ IP range CVE mapping helpers ------------------
def build_iprange_networks(nuclei_parsed: Dict[str, Dict[str, Any]]) -> Dict[str, ipaddress.IPv4Network]:
    nets: Dict[str, ipaddress.IPv4Network] = {}
    for root, block in nuclei_parsed.items():
        if block.get("root_type") != "iprange":
            continue
        try:
            net = ipaddress.ip_network(root, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                nets[root] = net
        except Exception:
            continue
    return nets

def best_matching_iprange(ip_str: str, nets: Dict[str, ipaddress.IPv4Network]) -> Optional[str]:
    """Zwraca najbardziej specyficzny CIDR (największy prefixlen) pasujący do IP."""
    if not is_ipv4(ip_str):
        return None
    ip_obj = ipaddress.ip_address(ip_str)
    best = None
    best_plen = -1
    for cidr, net in nets.items():
        try:
            if ip_obj in net and net.prefixlen > best_plen:
                best = cidr
                best_plen = net.prefixlen
        except Exception:
            continue
    return best

# ------------------ Build report ------------------
def build_report_for_root(root: str,
                          hosts_info: Dict[str, Dict[str, Any]],
                          artifacts_by_msg: Dict[str, List[Any]],
                          agg_recs: List[str],
                          cve_entries: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    lines.append(
        "Szanowni Państwo,\n"
        "w ramach analizy bezpieczeństwa teleinformatycznego w Państwa domenie zidentyfikowaliśmy obiekty, "
        "których wersja lub konfiguracja posiada znane podatności.\n"
    )

    sections = []
    if artifacts_by_msg:
        sections.append(("Kluczowe artefakty bezpieczeństwa", "artefacts"))
    any_svcs = any((h.get('services') and len(h.get('services')) > 0) for h in hosts_info.values())
    if any_svcs:
        sections.append(("Serwisy widoczne z sieci", "services"))
    if agg_recs:
        sections.append(("Kluczowe obserwacje i proponowane zabezpieczenia (serwisy)", "recs"))
    any_headers = any(h.get('missing_headers') for h in hosts_info.values())
    if any_headers:
        sections.append(("Brak nagłówków bezpieczeństwa", "headers"))
    if cve_entries:
        sections.append((f"Podatności wykryte na adresie: {root}", "cve"))

    if len(sections) > 1:
        lines.append("Spis treści:")
        for idx, (title, _) in enumerate(sections, 1):
            lines.append(f"{idx}. {title}")
        lines.append("")

    idx = 1

    # Artefakty
    if artifacts_by_msg:
        lines.append(f"{idx}. Kluczowe artefakty bezpieczeństwa:\n")
        for msg, reslist in artifacts_by_msg.items():
            lines.append(f"{msg}")

            normalized_map: Dict[str, str] = {}
            ctx_map: Dict[str, str] = {}

            for res in reslist:
                if isinstance(res, (list, tuple)) and len(res) >= 2:
                    resource, ctx = res[0], res[1]
                else:
                    resource, ctx = res, None

                if not resource:
                    continue

                norm = re.sub(r'^(www\.)', '', str(resource), flags=re.I)
                existing = normalized_map.get(norm)
                cur_is_www = bool(re.match(r'^\s*www\.', str(resource), re.I))
                existing_is_www = bool(existing and re.match(r'^\s*www\.', existing, re.I))

                if existing is None:
                    normalized_map[norm] = str(resource)
                    if ctx:
                        ctx_map[str(resource)] = str(ctx)
                else:
                    if existing_is_www and not cur_is_www:
                        normalized_map[norm] = str(resource)
                        if ctx:
                            ctx_map.pop(existing, None)
                            ctx_map[str(resource)] = str(ctx)
                    else:
                        if existing not in ctx_map and ctx:
                            ctx_map[existing] = str(ctx)

            host_entries = [normalized_map[k] for k in sorted(normalized_map.keys())]
            for h in host_entries:
                lines.append(f"\t* {h}")

            rec_full = None
            for _ptn, full_msg, _func in ARTIFACT_PATTERNS:
                title_check, _rec_check = split_artifact_msg(full_msg)
                if title_check == msg:
                    rec_full = full_msg
                    break

            if rec_full:
                if "->" in rec_full:
                    rec_short = rec_full.split("->", 1)[1].strip()
                else:
                    rec_short = rec_full
                lines.append(f"\t\tZalecamy:  {rec_short}")
            else:
                lines.append("\t\tZalecamy: natychmiastową weryfikację i aktualizację komponentu. Brak reakcji może prowadzić do RCE, wycieku danych lub eskalacji uprawnień\n")

            lines.append("")
        idx += 1

    # Serwisy
    if any_svcs:
        lines.append(f"{idx}. Serwisy widoczne z sieci (zagregowane):\n")
        svc_map = defaultdict(list)
        for host, h in hosts_info.items():
            services = h.get('services') or {}
            svc_entries = []
            for tag in sorted(services.keys()):
                raw_lines = services[tag].get('raw_lines', [])
                port = services[tag].get('port')
                norm_name = normalize_service_tag(tag, raw_lines)
                if port:
                    svc_entries.append(f"{norm_name} (port {port})")
                else:
                    svc_entries.append(f"{norm_name}")
            for svc in unique_preserve(svc_entries):
                svc_map[svc].append(host)

        def normalize_host(hostname: str) -> str:
            return re.sub(r'^(www\.)', '', hostname.strip(), flags=re.I)

        for svc, hosts in sorted(svc_map.items()):
            norm_map: Dict[str, str] = {}
            for h in hosts:
                norm = normalize_host(h)
                existing = norm_map.get(norm)
                cur_is_www = bool(re.match(r'^\s*www\.', h, re.I))
                existing_is_www = bool(existing and re.match(r'^\s*www\.', existing, re.I))
                if existing is None:
                    norm_map[norm] = h
                elif existing_is_www and not cur_is_www:
                    norm_map[norm] = h

            unique_hosts = sorted(norm_map.values())
            lines.append(f"{svc}: {', '.join(unique_hosts)}\n")
        idx += 1

    # Rekomendacje serwisowe
    if agg_recs:
        lines.append(f"{idx}. Kluczowe obserwacje i proponowane zabezpieczenia (serwisy):")
        for r in agg_recs:
            lines.append(f"\t{r}")
        lines.append("")
        idx += 1

    # Missing headers
    if any_headers:
        lines.append(f"{idx}. Brak nagłówków bezpieczeństwa:\n")
        all_missing = set()
        for h in hosts_info.values():
            all_missing.update(h.get('missing_headers', []))
        for hkey, desc in HEADER_DESCRIPTIONS.items():
            if hkey in all_missing:
                lines.append(f"{hkey} -> {desc}")
        lines.append("")

        domain_missing_map = {}
        for host, h in hosts_info.items():
            missing = set(h.get('missing_headers', []))
            if missing:
                domain_missing_map[host] = missing

        grouped_domains = defaultdict(list)
        for domain, headers in domain_missing_map.items():
            key = tuple(sorted(headers))
            grouped_domains[key].append(domain)

        lines.append("Domeny z brakującymi nagłówkami:")
        for headers, domains in sorted(grouped_domains.items(), key=lambda x: x[1]):
            lines.append(f"{','.join(sorted(domains))}:")
            for h in headers:
                lines.append(f"- {h}")
            lines.append("")
        idx += 1

    # CVE
    if cve_entries:
        lines.append(f"{idx}. Podatności wykryte na adresie: {root}")
        merged = merge_cve_entries_per_host(cve_entries)
        ordered_hosts = list(merged.keys())
        main_host = root.lower()
        if main_host in ordered_hosts:
            ordered_hosts = [main_host] + [h for h in ordered_hosts if h != main_host]

        for host in ordered_hosts:
            if host == "__unknown__" or host.startswith("dmarc"):
                continue
            ent = merged[host]
            ips = ent.get('ips', [])
            primary_ip = ips[0] if ips else ""
            services_norm = ent.get('services')
            cves = ent.get('cves', []) or []
            cve_details = ent.get('cve_details', []) or []
            recs = ent.get('recs', []) or []

            # Every host/subdomain must be rendered. The previous implementation
            # printed CVE/IP data only when host == root and silently omitted it
            # for subdomains. Keep the same report structure for every host.
            display_host = root if host == main_host else host
            if primary_ip:
                lines.append(f"IP: {primary_ip} ({display_host})")
            else:
                lines.append(f"{display_host}")

            if services_norm:
                lines.append(f"Widoczne serwisy: {services_norm}")

            if cves or cve_details:
                lines.append("CVEs:")
                # Prefer full original nuclei finding lines where available so
                # URL, protocol, severity, route and other evidence are not lost.
                emitted_ids = set()
                for detail in cve_details:
                    if not detail:
                        continue
                    formatted_detail = format_nuclei_cve_finding(detail)
                    lines.append(f"\t{formatted_detail}")
                    for cv in re.findall(r'\b(CVE-\d{4}-\d{4,7})\b', formatted_detail, re.I):
                        emitted_ids.add(cv.upper())
                # CVE-folder entries may have only IDs/descriptions and no raw
                # nuclei line. Emit those IDs as a lossless fallback.
                for c in cves:
                    cid_match = re.search(r'\b(CVE-\d{4}-\d{4,7})\b', str(c), re.I)
                    cid = cid_match.group(1).upper() if cid_match else str(c).upper()
                    if cid not in emitted_ids:
                        lines.append(f"\t{c}")
                        emitted_ids.add(cid)

            if recs:
                lines.append("Rekomendacje / uwagi:")
                for r in recs:
                    r = r.replace(
                        f"Szanowni Państwo,\n"
                        f"w ramach analizy bezpieczeństwa teleinformatycznego w Państwa domenie {root} "
                        "zidentyfikowaliśmy obiekty, których wersja lub konfiguracja posiada znane podatności.",
                        ""
                    )
                    lines.append(f"\t {r}")
            lines.append("")
        idx += 1

    lines.append("Jeżeli któreś z podatności nie dotyczą podmiotu, prosimy o informację zwrotną wraz z wyjaśnieniem.\n")
    lines.append("Prosimy pamiętać, że skanowanie jest rozłożone w czasie.\n")
    if should_add_pgp(root):
        lines.append(PGP_ANSI + "Jednocześnie przypominamy o rekomendowanej formie komunikacji z wykorzystaniem szyfrowania wiadomości PGP." + PGP_RESET)
    lines.append("")
    return "\n".join(lines)

# ------------------ MAIN ------------------
def main():
    if len(sys.argv) != 4:
        print("Użycie: python3 raport_parser_subdomains_with_cve.py <nuclei_grouped.txt> <lista_domen.txt> <cve_folder_or_->")
        print("Podaj '-' zamiast folderu CVE, żeby pominąć parsowanie CVE.")
        sys.exit(1)

    nuclei_file = sys.argv[1]
    domains_file = sys.argv[2]
    cve_folder = sys.argv[3]

    if not os.path.isfile(nuclei_file):
        print(f"Brak pliku nuclei: {nuclei_file}")
        sys.exit(1)
    if not os.path.isfile(domains_file):
        print(f"Brak pliku z domenami: {domains_file}")
        sys.exit(1)

    roots = [ln.strip().lower() for ln in safe_read(domains_file).splitlines() if ln.strip()]
    if not roots:
        print("Brak root-domen w pliku domen.")
        sys.exit(1)

    nuclei_content = safe_read(nuclei_file)
    nuclei_content = clean_ansi(nuclei_content)
    nuclei_parsed = parse_nuclei_blocks(nuclei_content)

    # IP range roots present in nuclei_grouped
    iprange_nets = build_iprange_networks(nuclei_parsed)
    iprange_roots = list(iprange_nets.keys())

    # CVE mode
    cve_mode = True
    cve_by_root = defaultdict(list)
    if cve_folder == "-" or cve_folder is None:
        cve_mode = False
    else:
        if not os.path.isdir(cve_folder):
            print(f"Uwaga: folder z CVE nie istnieje: {cve_folder}. Przełączam w tryb bez CVE.")
            cve_mode = False

    # CVE parse + mapping
    if cve_mode:
        for fname in os.listdir(cve_folder):
            if not fname.lower().endswith(".html"):
                continue
            path = os.path.join(cve_folder, fname)
            try:
                entries = parse_cve_html_file(path)
            except Exception as e:
                print(f"[!] Błąd parsowania {path}: {e}")
                entries = []

            if entries:
                entries = [e for e in entries if not is_example_entry(e)]

            base = os.path.splitext(fname)[0].lower()
            matched_roots = set()

            # 1) Filename-based mapping remains supported.
            for root in roots:
                if base == root or base.endswith("." + root) or root in base:
                    cve_by_root[root].extend(entries)
                    matched_roots.add(root)

            # 2) CONTENT-AWARE mapping.
            #    Every entry is checked for domains present inside the CVE HTML itself.
            #    This is the critical fix for files named e.g. report.html / 12345.html.
            for root in roots:
                matching_entries = [e for e in entries if _entry_mentions_root(e, root)]
                if matching_entries:
                    cve_by_root[root].extend(matching_entries)
                    matched_roots.add(root)

            # 3) IPv4 filename -> known IP-range bucket.
            if not matched_roots and is_ipv4(base) and iprange_nets:
                cidr = best_matching_iprange(base, iprange_nets)
                if cidr:
                    cve_by_root[cidr].extend(entries)
                    matched_roots.add(cidr)

            # 4) Lossless single-entity fallback.
            #    When this run contains one root only, ALL reports from its CVE folder
            #    belong to that entity and must never disappear merely because the
            #    filename/content format was unexpected.
            if not matched_roots and len(roots) == 1:
                cve_by_root[roots[0]].extend(entries)
                matched_roots.add(roots[0])

            # 5) Multi-root ambiguous fallback:
            #    preserve the data explicitly instead of silently dropping it.
            if not matched_roots:
                cve_by_root["__unmapped__"].extend(entries)

    out_dir = "sparsowane_raporty"
    os.makedirs(out_dir, exist_ok=True)

    # --------------------------
    # 1) DOMAIN REPORTS (as before)
    # --------------------------
    for root in roots:
        hosts_info: Dict[str, Dict[str, Any]] = {}

        # Zbieramy tylko z bloków typu 'domain' (Root domain)
        for parsed_root, block in nuclei_parsed.items():
            if block.get('root_type') != 'domain':
                continue
            for host, hinfo in (block.get('hosts', {}) or {}).items():
                # IPv4 hosty ignorujemy w raporcie domenowym (powinny być już zmapowane po stronie nuclei_parser_merged)
                if is_ipv4(host or ""):
                    continue
                if host == root or host.endswith("." + root):
                    hosts_info[host] = {
                        'ip': hinfo.get('ip'),
                        'raw_findings': (hinfo.get('raw_findings', []) or [])[:],
                        'services': (hinfo.get('services', {}) or {}),
                        'cves': (hinfo.get('cves', []) or [])[:],
                        'missing_headers': (hinfo.get('missing_headers', []) or [])[:]
                    }

        artifacts_by_msg: Dict[str, List[Any]] = {}
        for host, hinfo in hosts_info.items():
            for ln in hinfo.get('raw_findings', []):
                # CVE findings are rendered only in the standard CVEs section.
                # This prevents duplicate blocks such as "Wykryto podatnosc"
                # or plugin-specific duplicates for the same CVE.
                if re.search(r'\bCVE-\d{4}-\d{4,7}\b', ln, re.I):
                    continue

                for patt, msg, func in ARTIFACT_PATTERNS:
                    try:
                        m = patt.search(ln)
                        if not m:
                            continue

                        formatted_msg = msg
                        if '{0}' in (msg or ""):
                            try:
                                cve_val = None
                                if m and m.groups():
                                    cve_val = m.group(1).upper()
                                else:
                                    mm = re.search(r'\b(CVE-\d{4}-\d{4,7})\b', ln, re.I)
                                    if mm:
                                        cve_val = mm.group(1).upper()
                                if cve_val:
                                    formatted_msg = msg.format(cve_val)
                            except Exception:
                                pass

                        title_key, _rec = split_artifact_msg(formatted_msg)
                        found_cves_in_line = re.findall(r'\b(CVE-\d{4}-\d{4,7})\b', ln, re.I)
                        host_cves = hinfo.get('cves', []) or []

                        if 'wp-content/plugins' in (formatted_msg or "").lower() or 'plugin' in (formatted_msg or "").lower():
                            if not found_cves_in_line and not host_cves:
                                continue
                            cves_to_use = [c.upper() for c in found_cves_in_line] if found_cves_in_line else host_cves
                            for cv in unique_preserve(cves_to_use):
                                artifacts_by_msg.setdefault(cv, [])
                                entry = (host, ln.strip())
                                if entry not in artifacts_by_msg[cv]:
                                    artifacts_by_msg[cv].append(entry)
                            continue

                        artifacts_by_msg.setdefault(title_key, [])
                        added = False

                        if func and callable(func):
                            try:
                                extra = func(ln)
                                if extra:
                                    entry = (extra, ln.strip())
                                    if entry not in artifacts_by_msg[title_key]:
                                        artifacts_by_msg[title_key].append(entry)
                                        added = True
                            except Exception:
                                pass

                        if not added:
                            res = None
                            m_res = re.search(r'([a-z0-9\.-]+\.[a-z]{2,}[^\s\[\]"]*/[^\s\[\]"]+)', ln, re.I)
                            if m_res:
                                res = m_res.group(1).strip()
                            else:
                                res = extract_domain_from_line(ln) or host
                            entry = (res, ln.strip())
                            if entry not in artifacts_by_msg[title_key]:
                                artifacts_by_msg[title_key].append(entry)
                    except Exception:
                        continue

        agg_norm_services: List[str] = []
        for _host, hinfo in hosts_info.items():
            for tag, svc in (hinfo.get('services') or {}).items():
                norm = normalize_service_tag(tag, svc.get('raw_lines', []))
                if norm not in agg_norm_services:
                    agg_norm_services.append(norm)

        agg_recs: List[str] = []
        for norm in agg_norm_services:
            for key, msg in SERVICE_RECOMMENDATIONS.items():
                if key in norm and msg not in agg_recs:
                    agg_recs.append(msg)

        if any('ftp' in s for s in agg_norm_services) and SERVICE_RECOMMENDATIONS.get('ftp') not in agg_recs:
            agg_recs.append(SERVICE_RECOMMENDATIONS['ftp'])
        if any('ssh' in s for s in agg_norm_services) and SERVICE_RECOMMENDATIONS.get('ssh') not in agg_recs:
            agg_recs.append(SERVICE_RECOMMENDATIONS['ssh'])
        if any('http' in s for s in agg_norm_services) and SERVICE_RECOMMENDATIONS.get('http') not in agg_recs:
            agg_recs.append(SERVICE_RECOMMENDATIONS['http'])
        if any('postgres' in s for s in agg_norm_services) and SERVICE_RECOMMENDATIONS.get('postgresql') not in agg_recs:
            agg_recs.append(SERVICE_RECOMMENDATIONS.get('postgresql'))

        if cve_mode:
            cve_entries = _dedupe_cve_source_entries(cve_by_root.get(root, [])[:])
            for ent in cve_entries:
                if ent.get('cves'):
                    ent['cves'] = dedupe_cves_list(ent['cves'])
                if ent.get('services'):
                    ent['services'] = normalize_services_str(ent['services'])
        else:
            cve_entries = []

        # add nuclei CVEs into cve_entries (original behavior)
        for host, hinfo in hosts_info.items():
            for c in hinfo.get('cves', []):
                exists = False
                for ent in cve_entries:
                    if (ent.get('host') or "").lower() == host and c in (ent.get('cves') or []):
                        exists = True
                        break
                if exists:
                    matching_raw = [
                        ln for ln in (hinfo.get('raw_findings') or [])
                        if re.search(rf'\b{re.escape(c)}\b', ln, re.I)
                    ]
                    for ent in cve_entries:
                        if (ent.get('host') or "").lower() == host and c in (ent.get('cves') or []):
                            ent.setdefault('cve_details', [])
                            for detail in matching_raw:
                                if detail not in ent['cve_details']:
                                    ent['cve_details'].append(detail)
                    continue
                if not exists:
                    matching_raw = [
                        ln for ln in (hinfo.get('raw_findings') or [])
                        if re.search(rf'\b{re.escape(c)}\b', ln, re.I)
                    ]
                    cve_entries.append({
                        'ip': hinfo.get('ip'),
                        'host': host,
                        'services': ", ".join((hinfo.get('services') or {}).keys()),
                        'cves': [c],
                        'cve_details': unique_preserve(matching_raw),
                        'recs': []
                    })

        report_text = build_report_for_root(root, hosts_info, artifacts_by_msg, agg_recs, cve_entries)
        out_path = os.path.join(out_dir, f"{sanitize_filename(root)}.txt")
        with open(out_path, 'w', encoding=ENC) as f:
            f.write(report_text)
        print(f"[+] Zapisano raport dla {root} -> {out_path}")

    # --------------------------
    # 2) IP RANGE REPORTS (NEW)
    # --------------------------
    for cidr in iprange_roots:
        block = nuclei_parsed.get(cidr) or {}
        if block.get("root_type") != "iprange":
            continue

        hosts_info: Dict[str, Dict[str, Any]] = {}
        for host, hinfo in (block.get("hosts") or {}).items():
            # W raporcie IP-range uwzględniamy wszystko z tego kubełka (host może być IP lub domeną)
            hosts_info[host] = {
                'ip': hinfo.get('ip'),
                'raw_findings': (hinfo.get('raw_findings', []) or [])[:],
                'services': (hinfo.get('services', {}) or {}),
                'cves': (hinfo.get('cves', []) or [])[:],
                'missing_headers': (hinfo.get('missing_headers', []) or [])[:]
            }

        artifacts_by_msg: Dict[str, List[Any]] = {}
        for host, hinfo in hosts_info.items():
            for ln in hinfo.get('raw_findings', []):
                for patt, msg, func in ARTIFACT_PATTERNS:
                    try:
                        m = patt.search(ln)
                        if not m:
                            continue

                        formatted_msg = msg
                        if '{0}' in (msg or ""):
                            try:
                                cve_val = None
                                if m and m.groups():
                                    cve_val = m.group(1).upper()
                                else:
                                    mm = re.search(r'\b(CVE-\d{4}-\d{4,7})\b', ln, re.I)
                                    if mm:
                                        cve_val = mm.group(1).upper()
                                if cve_val:
                                    formatted_msg = msg.format(cve_val)
                            except Exception:
                                pass

                        title_key, _rec = split_artifact_msg(formatted_msg)
                        found_cves_in_line = re.findall(r'\b(CVE-\d{4}-\d{4,7})\b', ln, re.I)
                        host_cves = hinfo.get('cves', []) or []

                        if 'wp-content/plugins' in (formatted_msg or "").lower() or 'plugin' in (formatted_msg or "").lower():
                            if not found_cves_in_line and not host_cves:
                                continue
                            cves_to_use = [c.upper() for c in found_cves_in_line] if found_cves_in_line else host_cves
                            for cv in unique_preserve(cves_to_use):
                                artifacts_by_msg.setdefault(cv, [])
                                entry = (host, ln.strip())
                                if entry not in artifacts_by_msg[cv]:
                                    artifacts_by_msg[cv].append(entry)
                            continue

                        artifacts_by_msg.setdefault(title_key, [])
                        added = False

                        if func and callable(func):
                            try:
                                extra = func(ln)
                                if extra:
                                    entry = (extra, ln.strip())
                                    if entry not in artifacts_by_msg[title_key]:
                                        artifacts_by_msg[title_key].append(entry)
                                        added = True
                            except Exception:
                                pass

                        if not added:
                            res = None
                            m_res = re.search(r'([a-z0-9\.-]+\.[a-z]{2,}[^\s\[\]"]*/[^\s\[\]"]+)', ln, re.I)
                            if m_res:
                                res = m_res.group(1).strip()
                            else:
                                res = extract_domain_from_line(ln) or host
                            entry = (res, ln.strip())
                            if entry not in artifacts_by_msg[title_key]:
                                artifacts_by_msg[title_key].append(entry)
                    except Exception:
                        continue

        agg_norm_services: List[str] = []
        for _host, hinfo in hosts_info.items():
            for tag, svc in (hinfo.get('services') or {}).items():
                norm = normalize_service_tag(tag, svc.get('raw_lines', []))
                if norm not in agg_norm_services:
                    agg_norm_services.append(norm)

        agg_recs: List[str] = []
        for norm in agg_norm_services:
            for key, msg in SERVICE_RECOMMENDATIONS.items():
                if key in norm and msg not in agg_recs:
                    agg_recs.append(msg)

        if any('ftp' in s for s in agg_norm_services) and SERVICE_RECOMMENDATIONS.get('ftp') not in agg_recs:
            agg_recs.append(SERVICE_RECOMMENDATIONS['ftp'])
        if any('ssh' in s for s in agg_norm_services) and SERVICE_RECOMMENDATIONS.get('ssh') not in agg_recs:
            agg_recs.append(SERVICE_RECOMMENDATIONS['ssh'])
        if any('http' in s for s in agg_norm_services) and SERVICE_RECOMMENDATIONS.get('http') not in agg_recs:
            agg_recs.append(SERVICE_RECOMMENDATIONS['http'])
        if any('postgres' in s for s in agg_norm_services) and SERVICE_RECOMMENDATIONS.get('postgresql') not in agg_recs:
            agg_recs.append(SERVICE_RECOMMENDATIONS.get('postgresql'))

        # CVE entries assigned to this CIDR (from CVE HTML mapping stage)
        if cve_mode:
            cve_entries = _dedupe_cve_source_entries(cve_by_root.get(cidr, [])[:])
            for ent in cve_entries:
                if ent.get('cves'):
                    ent['cves'] = dedupe_cves_list(ent['cves'])
                if ent.get('services'):
                    ent['services'] = normalize_services_str(ent['services'])
        else:
            cve_entries = []

        # Add nuclei-detected CVEs into cve_entries as well (for IPs/domains inside this CIDR bucket)
        for host, hinfo in hosts_info.items():
            for c in hinfo.get('cves', []):
                exists = False
                for ent in cve_entries:
                    if (ent.get('host') or "").lower() == host and c in (ent.get('cves') or []):
                        exists = True
                        break
                if exists:
                    matching_raw = [
                        ln for ln in (hinfo.get('raw_findings') or [])
                        if re.search(rf'\b{re.escape(c)}\b', ln, re.I)
                    ]
                    for ent in cve_entries:
                        if (ent.get('host') or "").lower() == host and c in (ent.get('cves') or []):
                            ent.setdefault('cve_details', [])
                            for detail in matching_raw:
                                if detail not in ent['cve_details']:
                                    ent['cve_details'].append(detail)
                    continue
                if not exists:
                    matching_raw = [
                        ln for ln in (hinfo.get('raw_findings') or [])
                        if re.search(rf'\b{re.escape(c)}\b', ln, re.I)
                    ]
                    cve_entries.append({
                        'ip': hinfo.get('ip'),
                        'host': host,
                        'services': ", ".join((hinfo.get('services') or {}).keys()),
                        'cves': [c],
                        'cve_details': unique_preserve(matching_raw),
                        'recs': []
                    })

        report_text = build_report_for_root(cidr, hosts_info, artifacts_by_msg, agg_recs, cve_entries)
        out_path = os.path.join(out_dir, f"{sanitize_filename(cidr)}.txt")
        with open(out_path, 'w', encoding=ENC) as f:
            f.write(report_text)
        print(f"[+] Zapisano raport dla {cidr} -> {out_path}")

    # Unmapped CVEs dump (original behavior preserved)
    if cve_mode:
        unm = cve_by_root.get("__unmapped__", [])
        if unm:
            try:
                p = os.path.join(out_dir, "unmapped_cve_entries.txt")
                with open(p, 'w', encoding=ENC) as f:
                    for e in unm:
                        f.write(str(e) + "\n")
                print(f"[!] Nieprzypisane CVE zapisane -> {p}")
            except Exception:
                pass

if __name__ == "__main__":
    main()

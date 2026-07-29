#!/usr/bin/env python3
"""
nuclei_parser_merged.py

Usage:
  python3 nuclei_parser_merged.py nuclei_scan.txt ip_mapping.txt

What it does:
- Parses Nuclei output and groups findings into ONE output file: nuclei_grouped.txt
- Supports both:
  - domain/URL targets (subdomains, host:port/path, http(s)://...)
  - IPv4 targets
- Uses the mapping file to assign IPv4 findings to the correct domain group(s).
  - If an IPv4 matches multiple mapped domain groups, it automatically disambiguates using:
    - Forward DNS (A record): does any candidate domain resolve to this IP?
    - Reverse DNS (PTR): does the IP’s PTR name belong to a candidate domain?
    - Optional ping parsing (best-effort, if ping exists): does ping show this IP for a candidate domain?
  - If still tied, it picks the most specific rule (smallest CIDR / smallest range), then first group in mapping order.

Mapping file format (entries can be on separate lines OR separated by whitespace):
  aaa.pl:1.1.1.1,2.2.2.2,3.3.3.3,9.8.8.8/16,6.7.7.7-7.7.7.100
  bbb.pl,bbb.eu,bbb.zzz.pl:4.4.4.4,7.7.7.7-7.7.7.100
  ccc.pl:5.5.5.5-5.5.5.30
  ddd.pl:6.6.6.6/28

Notes:
- Skips bracketed noise tokens like [info] or (tcp)
- Skips Nuclei DNS module lines ([dns])
- Unmapped IPv4s are grouped into /24 ranges (configurable via IP_GROUP_PREFIX).
"""

import socket
import sys
import os
import re
import ipaddress
import subprocess
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional, Set, Union

OUTPUT_FILE = "nuclei_grouped.txt"
IP_GROUP_PREFIX = 24  # fallback grouping for unmapped IPv4s

# ------------------------------
# Utilities: IP / DNS
# ------------------------------
def is_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False

def ipv4_range_label(ip_str: str, prefix: int = IP_GROUP_PREFIX) -> str:
    net = ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)
    return net.with_prefixlen

def get_ip(host: str) -> str:
    """Resolve hostname to IPv4 (best-effort)."""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return "Unknown"

def normalize_fqdn(name: str) -> str:
    return name.strip().lower().rstrip(".")

def ptr_lookup(ip_str: str) -> Optional[str]:
    """Reverse DNS PTR lookup."""
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        return normalize_fqdn(host)
    except Exception:
        return None

def forward_ipv4_lookup(domain: str) -> Set[str]:
    """Forward DNS A lookup via getaddrinfo. Returns set of IPv4 strings."""
    domain = normalize_fqdn(domain)
    ips: Set[str] = set()
    try:
        res = socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        for r in res:
            sockaddr = r[4]
            if sockaddr and len(sockaddr) >= 1:
                ips.add(sockaddr[0])
    except Exception:
        pass
    return ips

def ping_resolved_ip(domain: str, timeout_s: int = 2) -> Optional[str]:
    """
    Best-effort ping parse for "PING domain (x.x.x.x)".
    If ping doesn't exist or parsing fails, returns None.
    """
    domain = normalize_fqdn(domain)
    # Linux ping commonly supports -c and -W. If not, fail silently.
    cmd = ["ping", "-c", "1", "-W", str(timeout_s), domain]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 1)
        out = (p.stdout or "") + "\n" + (p.stderr or "")
        m = re.search(r"PING\s+\S+\s+\((\d{1,3}(?:\.\d{1,3}){3})\)", out, re.IGNORECASE)
        if m:
            return m.group(1)
    except Exception:
        return None
    return None

# ------------------------------
# Registered domain helper (tldextract if available)
# ------------------------------
KNOWN_TWO_LEVEL_TLDS = {
    "mil.pl", "gov.pl", "edu.pl", "com.pl",
    "co.uk", "gov.uk", "ac.uk", "org.uk",
    "com.au", "gov.au", "edu.au",
}

def get_registered_domain(host: str) -> str:
    host = host.lower()
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        return host

    try:
        import tldextract  # type: ignore
        ext = tldextract.extract(host)
        reg = None
        if hasattr(ext, "top_domain_under_public_suffix") and ext.top_domain_under_public_suffix:
            reg = ext.top_domain_under_public_suffix
        elif hasattr(ext, "registered_domain") and ext.registered_domain:
            reg = ext.registered_domain
        if reg:
            return reg
    except Exception:
        pass

    parts = host.split(".")
    if len(parts) < 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in KNOWN_TWO_LEVEL_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

# ------------------------------
# Robust parsing of URL-ish target tokens
# ------------------------------
def clean_token_surroundings(token: str) -> str:
    if not token:
        return token
    token = token.strip()
    token = token.strip(" \t\n\r'\"")
    while token and token[0] in "[(<\"'":
        token = token[1:].lstrip()
    while token and token[-1] in "])>\"'.,;:":
        token = token[:-1].rstrip()
    return token

def looks_like_non_url_bracketed(token: str) -> bool:
    if not token:
        return False
    if (token.startswith("[") and token.endswith("]")) or (token.startswith("(") and token.endswith(")")):
        inner = token[1:-1].strip()
        if "." not in inner and ":" not in inner and len(inner) <= 20 and inner.isalpha():
            return True
    return False

def parse_raw_url_token(token: str) -> Tuple[Optional[str], Optional[int], str, str]:
    """
    Returns: (host, port, path, original_token)
    """
    if not token:
        return None, None, "", token

    original = token
    token = clean_token_surroundings(token)

    if looks_like_non_url_bracketed(original) or looks_like_non_url_bracketed(token):
        return None, None, "", original

    if len(token) <= 3 and token.isalpha():
        return None, None, "", original

    parsed = None
    try:
        if token.startswith("http://") or token.startswith("https://"):
            parsed = urlparse(token)
        else:
            parsed = urlparse("http://" + token)
    except ValueError:
        parsed = None

    host = None
    port = None
    path = ""

    if parsed:
        host = parsed.hostname
        port = parsed.port
        path = parsed.path or ""
        if parsed.query:
            path += "?" + parsed.query
        if parsed.fragment:
            path += "#" + parsed.fragment

    if not host:
        s = token.split("/", 1)
        hostport = s[0]
        if len(s) > 1:
            path = "/" + s[1]

        if "@" in hostport:
            hostport = hostport.split("@")[-1]

        if ":" in hostport:
            if hostport.startswith("[") and "]" in hostport:
                m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", hostport)
                if m:
                    host = m.group(1)
                    port = int(m.group(2)) if m.group(2) else None
            else:
                hp = hostport.split(":")
                if hp[-1].isdigit():
                    port = int(hp[-1])
                    host = ":".join(hp[:-1])
                else:
                    host = hostport
        else:
            host = hostport

    if host:
        host = host.strip().strip("[]")
        if host.isalpha() and "." not in host and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            return None, None, "", original
        return host.lower(), port, path, original

    return None, None, "", original

# ------------------------------
# Mapping parsing
# ------------------------------
IpRule = Union[ipaddress.IPv4Network, Tuple[int, int]]  # network or (start_int, end_int)

def _parse_ip_rule(item: str) -> Optional[IpRule]:
    """
    item can be:
      - single IPv4: 1.2.3.4
      - CIDR: 1.2.0.0/16
      - range: 1.2.3.4-1.2.3.99
    """
    item = item.strip()
    if not item:
        return None

    if "/" in item:
        try:
            net = ipaddress.ip_network(item, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                return net
        except ValueError:
            return None
        return None

    if "-" in item:
        a, b = item.split("-", 1)
        a, b = a.strip(), b.strip()
        try:
            ia = ipaddress.ip_address(a)
            ib = ipaddress.ip_address(b)
            if not (isinstance(ia, ipaddress.IPv4Address) and isinstance(ib, ipaddress.IPv4Address)):
                return None
            sa, sb = int(ia), int(ib)
            if sa > sb:
                sa, sb = sb, sa
            return (sa, sb)
        except ValueError:
            return None

    try:
        ip = ipaddress.ip_address(item)
        if isinstance(ip, ipaddress.IPv4Address):
            v = int(ip)
            return (v, v)
    except ValueError:
        return None

    return None

def _extract_mapping_entries(text: str) -> List[Tuple[str, str]]:
    """
    Robustly extracts (left, right) pairs even if entries are separated by whitespace instead of newlines.
    We look for patterns of the form:
        <domains> : <ips>
    where <domains> has no spaces/colons and can contain commas.
    """
    # Remove comments
    cleaned_lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # strip inline comments
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if line:
            cleaned_lines.append(line)
    cleaned = " ".join(cleaned_lines).strip()

    if not cleaned:
        return []

    # Find all occurrences of "<something>:"
    # domain part has no whitespace/colon, may include commas and dots.
    pattern = re.compile(r"(?P<left>[^\s:]+)\s*:")
    matches = list(pattern.finditer(cleaned))
    if not matches:
        return []

    entries: List[Tuple[str, str]] = []
    for i, m in enumerate(matches):
        left = m.group("left").strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(cleaned)
        right = cleaned[start:end].strip()
        if left and right:
            entries.append((left, right))
    return entries

def load_mapping_file(path: str) -> Tuple[
    Dict[str, str],              # alias -> group_label
    Dict[str, List[str]],        # group_label -> aliases (ordered)
    Dict[str, List[IpRule]],     # group_label -> ip rules
    List[str]                    # group order
]:
    """
    Each entry:
      domains_csv:ip_list_csv
    domains_csv can contain multiple aliases separated by commas.
    group_label is the FIRST domain in domains_csv.
    """
    with open(path, "r", errors="ignore") as f:
        text = f.read()

    entries = _extract_mapping_entries(text)

    alias_to_group: Dict[str, str] = {}
    group_to_aliases: Dict[str, List[str]] = {}
    group_to_rules: Dict[str, List[IpRule]] = {}
    group_order: List[str] = []

    for left, right in entries:
        aliases = [normalize_fqdn(x) for x in left.split(",") if x.strip()]
        if not aliases:
            continue
        group = aliases[0]
        if group not in group_order:
            group_order.append(group)

        # alias -> group
        for a in aliases:
            alias_to_group[a] = group

        # group -> aliases (preserve order)
        prev_aliases = group_to_aliases.get(group, [])
        for a in aliases:
            if a not in prev_aliases:
                prev_aliases.append(a)
        group_to_aliases[group] = prev_aliases

        # parse IP items
        ip_items = [x.strip() for x in right.split(",") if x.strip()]
        rules = group_to_rules.get(group, [])
        for item in ip_items:
            rule = _parse_ip_rule(item)
            if rule is not None:
                rules.append(rule)
        group_to_rules[group] = rules

    return alias_to_group, group_to_aliases, group_to_rules, group_order

def ip_in_rule(ip_int: int, rule: IpRule) -> bool:
    if isinstance(rule, ipaddress.IPv4Network):
        return ipaddress.IPv4Address(ip_int) in rule
    start, end = rule
    return start <= ip_int <= end

def groups_for_ip(ip_str: str, group_to_rules: Dict[str, List[IpRule]]) -> List[str]:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if not isinstance(ip_obj, ipaddress.IPv4Address):
            return []
        ip_int = int(ip_obj)
    except ValueError:
        return []

    hits: List[str] = []
    for grp, rules in group_to_rules.items():
        for rule in rules:
            if ip_in_rule(ip_int, rule):
                hits.append(grp)
                break
    return hits

def mapped_group_for_domain(host: str, alias_to_group: Dict[str, str]) -> Optional[str]:
    """Exact or suffix match against mapping aliases."""
    if not alias_to_group:
        return None
    h = normalize_fqdn(host)

    if h in alias_to_group:
        return alias_to_group[h]

    for alias, grp in alias_to_group.items():
        if h == alias or h.endswith("." + alias):
            return grp
    return None

def rule_specificity(rule: IpRule) -> int:
    """
    Higher = more specific.
    - CIDR: higher prefixlen = more specific (score = 100000 + prefixlen)
    - range/single: smaller span = more specific (score = 100000 - span, min 0)
    """
    if isinstance(rule, ipaddress.IPv4Network):
        return 100000 + int(rule.prefixlen)
    start, end = rule
    span = max(0, end - start)
    return max(0, 100000 - span)

def best_specificity_for_group(ip_str: str, group: str, group_to_rules: Dict[str, List[IpRule]]) -> int:
    """Return the best (highest) specificity among rules in group that match ip_str."""
    try:
        ip_int = int(ipaddress.ip_address(ip_str))
    except ValueError:
        return 0
    best = 0
    for rule in group_to_rules.get(group, []):
        if ip_in_rule(ip_int, rule):
            best = max(best, rule_specificity(rule))
    return best

def choose_best_group_for_ip(
    ip_str: str,
    candidates: List[str],
    group_to_aliases: Dict[str, List[str]],
    group_to_rules: Dict[str, List[IpRule]],
    group_order: List[str],
    cache_forward: Dict[str, Set[str]],
    cache_ptr: Dict[str, Optional[str]],
    cache_ping: Dict[str, Optional[str]],
) -> str:
    """
    Always returns ONE chosen group using:
      1) Forward DNS A match (strong signal)
      2) PTR suffix match
      3) ping parse match (best-effort)
      4) most specific rule
      5) first in mapping file order
    """
    if len(candidates) == 1:
        return candidates[0]

    # PTR once
    if ip_str not in cache_ptr:
        cache_ptr[ip_str] = ptr_lookup(ip_str)
    ptr_name = cache_ptr[ip_str]

    best_score = None
    best_groups: List[str] = []

    for grp in candidates:
        aliases = group_to_aliases.get(grp, [grp])

        score = 0

        # Forward DNS match
        forward_hit = False
        for a in aliases:
            if a not in cache_forward:
                cache_forward[a] = forward_ipv4_lookup(a)
            if ip_str in cache_forward[a]:
                forward_hit = True
                break
        if forward_hit:
            score += 100

        # PTR suffix match
        if ptr_name:
            for a in aliases:
                a_norm = normalize_fqdn(a)
                if ptr_name == a_norm or ptr_name.endswith("." + a_norm):
                    score += 30
                    break

        # Ping parse match (best-effort; cached; harmless if missing)
        ping_hit = False
        for a in aliases:
            if a not in cache_ping:
                cache_ping[a] = ping_resolved_ip(a)
            if cache_ping[a] == ip_str:
                ping_hit = True
                break
        if ping_hit:
            score += 50

        # Add specificity as tie-breaker-friendly component
        score += best_specificity_for_group(ip_str, grp, group_to_rules) // 1000  # keep it small

        if best_score is None or score > best_score:
            best_score = score
            best_groups = [grp]
        elif score == best_score:
            best_groups.append(grp)

    if len(best_groups) == 1:
        return best_groups[0]

    # Still tied: prefer most specific rule
    best_spec = -1
    spec_best: List[str] = []
    for grp in best_groups:
        spec = best_specificity_for_group(ip_str, grp, group_to_rules)
        if spec > best_spec:
            best_spec = spec
            spec_best = [grp]
        elif spec == best_spec:
            spec_best.append(grp)
    if len(spec_best) == 1:
        return spec_best[0]

    # Final tie-break: mapping order
    order_index = {g: i for i, g in enumerate(group_order)}
    spec_best.sort(key=lambda g: order_index.get(g, 10**9))
    return spec_best[0]

# ------------------------------
# Main parse / group logic
# ------------------------------
def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: python3 nuclei_parser_merged.py nuclei_scan.txt ip_mapping.txt")
        return 1

    nuclei_file = sys.argv[1]
    mapping_file = sys.argv[2]

    if not os.path.isfile(nuclei_file):
        print(f"Error: File '{nuclei_file}' does not exist.")
        return 1
    if not os.path.isfile(mapping_file):
        print(f"Error: File '{mapping_file}' does not exist.")
        return 1

    alias_to_group, group_to_aliases, group_to_rules, group_order = load_mapping_file(mapping_file)

    # caches (only used when an IP overlaps)
    cache_forward: Dict[str, Set[str]] = {}
    cache_ptr: Dict[str, Optional[str]] = {}
    cache_ping: Dict[str, Optional[str]] = {}

    # grouped_data: root_group -> host -> list of entries
    # entry = (content_type_severity, original_token, extras)
    grouped_data: Dict[str, Dict[str, List[Tuple[List[str], str, List[str]]]]] = {}
    seen_root_order: List[str] = []

    with open(nuclei_file, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            # skip DNS module lines
            second_field = parts[1].strip("[]").lower()
            if second_field == "dns":
                continue

            raw_token = parts[3]
            host, port, path, original_token = parse_raw_url_token(raw_token)
            if not host:
                continue

            content_type_severity = parts[:3]
            extras: List[str] = []
            if port:
                extras.append(f"[port: {port}]")
            if path:
                extras.append(path)
            extras.extend(parts[4:])

            host_lower = host.lower()

            # Decide root group
            if is_ipv4(host_lower):
                mapped_candidates = groups_for_ip(host_lower, group_to_rules)

                if mapped_candidates:
                    if len(mapped_candidates) == 1:
                        root_group = mapped_candidates[0]
                    else:
                        root_group = choose_best_group_for_ip(
                            ip_str=host_lower,
                            candidates=mapped_candidates,
                            group_to_aliases=group_to_aliases,
                            group_to_rules=group_to_rules,
                            group_order=group_order,
                            cache_forward=cache_forward,
                            cache_ptr=cache_ptr,
                            cache_ping=cache_ping,
                        )
                        extras.append(f"[disambiguated-from: {','.join(mapped_candidates)}]")
                        extras.append(f"[chosen-group: {root_group}]")
                else:
                    # fallback: /24 group
                    root_group = ipv4_range_label(host_lower, IP_GROUP_PREFIX)
            else:
                # domain host: if it matches mapping aliases, group by mapping group; else registered domain
                mg = mapped_group_for_domain(host_lower, alias_to_group)
                root_group = mg if mg else get_registered_domain(host_lower)

            # store
            if root_group not in grouped_data:
                grouped_data[root_group] = {}
                if root_group not in seen_root_order:
                    seen_root_order.append(root_group)

            if host_lower not in grouped_data[root_group]:
                grouped_data[root_group][host_lower] = []

            grouped_data[root_group][host_lower].append((content_type_severity, original_token, extras))

    # Output order:
    # 1) mapping groups in file order
    # 2) any additional groups encountered (e.g., /24 fallbacks or non-mapped registered domains)
    roots_ordered = group_order + [r for r in seen_root_order if r not in group_order]

    # For deterministic output, if mapping file is empty or didn't parse, fall back to stable ordering
    if not roots_ordered:
        cidr_roots = sorted([r for r in grouped_data.keys() if "/" in r])
        domain_roots = sorted([r for r in grouped_data.keys() if "/" not in r])
        roots_ordered = cidr_roots + domain_roots

    with open(OUTPUT_FILE, "w") as out_f:
        for root in roots_ordered:
            if root not in grouped_data:
                continue

            header = "=== IP range" if "/" in root else "=== Root domain"
            out_f.write(f"{header}: {root} ===\n")

            hosts_map = grouped_data[root]

            # Sort hosts: numeric for IP-only roots, otherwise by domain depth
            if "/" in root:
                def ip_sort_key(h: str):
                    try:
                        return int(ipaddress.ip_address(h))
                    except ValueError:
                        return 10**18
                hosts_sorted = sorted(hosts_map.keys(), key=ip_sort_key)
            else:
                hosts_sorted = sorted(hosts_map.keys(), key=lambda h: (h.count("."), h))

            for h in hosts_sorted:
                ip_display = h if is_ipv4(h) else get_ip(h)
                out_f.write(f"  {ip_display} ({h}):\n")
                for cts, orig_tok, ex in hosts_map[h]:
                    line_to_print = "      " + " ".join(cts) + " " + orig_tok
                    if ex:
                        line_to_print += " " + " ".join(ex)
                    out_f.write(line_to_print + "\n")
                out_f.write("\n")

            out_f.write("\n")

    print(f"Grouped report saved to '{OUTPUT_FILE}'")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

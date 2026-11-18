#!/usr/bin/env python3
"""Bounded passive-OSINT worker for reconx Phase 1.

Every source is independently timed, failure-isolated, and emits a compact JSON
summary. Credentials are read only from the environment, are never placed in
worker output, and source snippets/possible secrets are reduced to redacted
metadata. The worker intentionally limits third-party API requests, DNS packet
sizes, AXFR records, and social-account lookups.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable

TIMEOUT_SECONDS = 8
MAX_HTTP_BYTES = 4 * 1024 * 1024
MAX_IPS = 20
MAX_RESULTS = 100
MAX_SEARCH_QUERIES = 12
MAX_AXFR_BYTES = 2 * 1024 * 1024
MAX_AXFR_RECORDS = 5_000
USER_AGENT = os.environ.get("RECONX_USER_AGENT", "reconx/1.0 passive-osint")
DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b")
SECRET_LABEL_RE = re.compile(r"(?i)\b(?:api[_ -]?key|secret|password|token|authorization|aws_access_key)\b")
URLSCAN_UUID_RE = re.compile(r"^[a-f0-9-]{32,64}$", re.IGNORECASE)
DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "NAPTR": 35, "CAA": 257, "AXFR": 252}
DNS_TYPE_NAMES = {value: key for key, value in DNS_TYPES.items()}


def skipped(reason: str) -> dict[str, str]:
    return {"skipped": reason}


def disabled(reason: str) -> dict[str, str]:
    return {"disabled": reason}


def bounded(values: list[Any], maximum: int = MAX_RESULTS) -> list[Any]:
    return values[:maximum]


def unique_strings(values: list[str]) -> list[str]:
    return sorted({value.strip().lower().rstrip(".") for value in values if isinstance(value, str) and value.strip()})


def public_ips(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        # Private, loopback, documentation, multicast, and link-local
        # addresses do not have useful global passive-source records.
        if not address.is_global:
            continue
        output.append(str(address))
    return unique_strings(output)[:MAX_IPS]


def clean_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(value):
        raise ValueError("target must be a domain or IP address")
    return value


def safe_text(value: Any, limit: int = 512) -> str:
    """Return compact evidence without retaining likely credential values."""
    text = str(value).replace("\x00", " ").replace("\r", " ").replace("\n", " ").strip()
    if SECRET_LABEL_RE.search(text):
        return "[REDACTED: potential credential-like content]"
    return text[:limit]


def request_bytes(url: str, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers)
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS, context=context) as response:
            data = response.read(MAX_HTTP_BYTES + 1)
            if len(data) > MAX_HTTP_BYTES:
                raise RuntimeError("response exceeds bounded passive-OSINT limit")
            return response.status, data
    except urllib.error.HTTPError as exc:
        data = exc.read(MAX_HTTP_BYTES + 1)
        if len(data) > MAX_HTTP_BYTES:
            data = b""
        return exc.code, data


def http_json(url: str, headers: dict[str, str] | None = None, accepted: tuple[int, ...] = (200,)) -> Any:
    status, data = request_bytes(url, headers)
    if status not in accepted:
        raise RuntimeError(f"HTTP {status}")
    if not data:
        return {}
    return json.loads(data.decode("utf-8", errors="replace"))


def query_whois(server: str, query: str) -> str:
    with socket.create_connection((server, 43), timeout=TIMEOUT_SECONDS) as connection:
        connection.sendall((query + "\r\n").encode("ascii", errors="ignore"))
        data = bytearray()
        while len(data) < 1_000_000:
            chunk = connection.recv(8192)
            if not chunk:
                break
            data.extend(chunk)
    return data.decode("utf-8", errors="replace")


def value_after(lines: list[str], labels: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    normalized_labels = {label.lower() for label in labels}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() in normalized_labels and value.strip():
            values.append(value.strip())
    return sorted(set(values))


def first(values: list[str]) -> str:
    return values[0] if values else ""


def whois(domain: str) -> dict[str, Any]:
    if not domain:
        return skipped("WHOIS requires a domain target")
    root = query_whois("whois.iana.org", domain)
    referral = ""
    for line in root.splitlines():
        if line.lower().startswith("refer:"):
            referral = line.split(":", 1)[1].strip().rstrip(".")
            break
    if referral and not DOMAIN_RE.fullmatch(referral):
        raise RuntimeError("WHOIS referral is not a valid hostname")
    text = query_whois(referral, domain) if referral else root
    lines = text.splitlines()
    emails = sorted({email.lower() for email in EMAIL_RE.findall(text)})[:50]
    result = {
        "server": referral or "whois.iana.org",
        "registrar": first(value_after(lines, ("registrar", "registrar name"))),
        "registrant_organization": first(value_after(lines, ("registrant organization", "registrant org", "org"))),
        "created": first(value_after(lines, ("creation date", "created date", "created on", "registered"))),
        "expires": first(value_after(lines, ("registry expiry date", "expiry date", "expiration date", "expires on", "paid-till"))),
        "nameservers": value_after(lines, ("name server", "nserver")),
        "emails": emails,
        "contact_domains": sorted({email.rsplit("@", 1)[-1] for email in emails}),
    }
    return {key: value for key, value in result.items() if value not in ("", [], None)}


# DNS wire-format support keeps Phase 1 portable and avoids a mandatory Python
# dependency. It uses the system-configured recursive resolver and only sends
# normal record lookups; AXFR is separately gated and bounded.
def resolver_addresses() -> list[str]:
    nameservers: list[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 2 and fields[0] == "nameserver":
                    try:
                        nameservers.append(str(ipaddress.ip_address(fields[1])))
                    except ValueError:
                        continue
    except OSError:
        pass
    return unique_strings(nameservers)[:3]


def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    labels = name.split(".")
    if not labels or any(not label or len(label.encode("idna")) > 63 for label in labels):
        raise ValueError("invalid DNS name")
    output = bytearray()
    for label in labels:
        encoded = label.encode("idna")
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    return bytes(output)


def make_dns_query(name: str, record_type: int) -> tuple[int, bytes]:
    query_id = random.SystemRandom().randint(0, 65535)
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    return query_id, header + encode_name(name) + struct.pack("!HH", record_type, 1)


def read_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    original_offset = offset
    jumped = False
    jumps = 0
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer >= len(packet) or jumps >= 20:
                raise ValueError("invalid DNS compression pointer")
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
            jumps += 1
            continue
        if length & 0xC0:
            raise ValueError("invalid DNS label")
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), original_offset if jumped else offset
        if offset + length > len(packet):
            raise ValueError("truncated DNS label")
        # DNS labels are wire-format ASCII/punycode. Decode conservatively;
        # the IDNA codec does not support replacement error handling.
        labels.append(packet[offset : offset + length].decode("ascii", errors="replace"))
        offset += length


def parse_character_string(packet: bytes, offset: int, end: int) -> tuple[str, int]:
    if offset >= end:
        raise ValueError("truncated DNS character string")
    length = packet[offset]
    offset += 1
    if offset + length > end:
        raise ValueError("truncated DNS character string data")
    return packet[offset : offset + length].decode("utf-8", errors="replace"), offset + length


def decode_rdata(packet: bytes, record_type: int, start: int, end: int) -> str:
    data = packet[start:end]
    if record_type == DNS_TYPES["A"]:
        return socket.inet_ntop(socket.AF_INET, data) if len(data) == 4 else ""
    if record_type == DNS_TYPES["AAAA"]:
        return socket.inet_ntop(socket.AF_INET6, data) if len(data) == 16 else ""
    if record_type in {DNS_TYPES["NS"], DNS_TYPES["CNAME"]}:
        value, _ = read_dns_name(packet, start)
        return value
    if record_type == DNS_TYPES["MX"]:
        if len(data) < 3:
            return ""
        preference = struct.unpack("!H", data[:2])[0]
        exchange, _ = read_dns_name(packet, start + 2)
        return f"{preference} {exchange}"
    if record_type == DNS_TYPES["SOA"]:
        mname, position = read_dns_name(packet, start)
        rname, position = read_dns_name(packet, position)
        if position + 20 > end:
            return ""
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", packet[position : position + 20])
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    if record_type == DNS_TYPES["TXT"]:
        chunks: list[str] = []
        position = start
        while position < end:
            value, position = parse_character_string(packet, position, end)
            chunks.append(value)
        return "".join(chunks)
    if record_type == DNS_TYPES["SRV"]:
        if len(data) < 7:
            return ""
        priority, weight, port = struct.unpack("!HHH", data[:6])
        target, _ = read_dns_name(packet, start + 6)
        return f"{priority} {weight} {port} {target}"
    if record_type == DNS_TYPES["NAPTR"]:
        if len(data) < 5:
            return ""
        order, preference = struct.unpack("!HH", data[:4])
        flags, position = parse_character_string(packet, start + 4, end)
        service, position = parse_character_string(packet, position, end)
        regexp, position = parse_character_string(packet, position, end)
        replacement, _ = read_dns_name(packet, position)
        return f"{order} {preference} {flags} {service} {regexp} {replacement}"
    if record_type == DNS_TYPES["CAA"]:
        if len(data) < 3:
            return ""
        flags = data[0]
        tag_length = data[1]
        if 2 + tag_length > len(data):
            return ""
        tag = data[2 : 2 + tag_length].decode("ascii", errors="replace")
        value = data[2 + tag_length :].decode("utf-8", errors="replace")
        return f"{flags} {tag} {value}"
    return ""


def parse_dns_packet(packet: bytes, expected_id: int | None = None) -> tuple[dict[str, list[str]], bool]:
    if len(packet) < 12:
        raise ValueError("truncated DNS header")
    query_id, flags, questions, answers, authority, additional = struct.unpack("!HHHHHH", packet[:12])
    if expected_id is not None and query_id != expected_id:
        raise ValueError("mismatched DNS response id")
    rcode = flags & 0x000F
    if rcode:
        raise RuntimeError(f"DNS RCODE {rcode}")
    truncated = bool(flags & 0x0200)
    offset = 12
    for _ in range(questions):
        _, offset = read_dns_name(packet, offset)
        if offset + 4 > len(packet):
            raise ValueError("truncated DNS question")
        offset += 4
    result: dict[str, list[str]] = {}
    total_records = answers + authority + additional
    if total_records > 10_000:
        raise ValueError("too many DNS records")
    for _ in range(total_records):
        _, offset = read_dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("truncated DNS record")
        record_type, record_class, _, length = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        end = offset + length
        if end > len(packet):
            raise ValueError("truncated DNS rdata")
        if record_class == 1:
            name = DNS_TYPE_NAMES.get(record_type)
            if name:
                value = decode_rdata(packet, record_type, offset, end)
                if value:
                    result.setdefault(name.lower(), []).append(value)
        offset = end
    return {key: sorted(set(values)) for key, values in result.items()}, truncated


def udp_dns_query(server: str, query: bytes, query_id: int) -> tuple[dict[str, list[str]], bool]:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as connection:
        connection.settimeout(TIMEOUT_SECONDS)
        connection.sendto(query, (server, 53))
        packet, _ = connection.recvfrom(65_535)
    return parse_dns_packet(packet, query_id)


def tcp_dns_query(server: str, query: bytes, query_id: int) -> tuple[dict[str, list[str]], bool]:
    with socket.create_connection((server, 53), timeout=TIMEOUT_SECONDS) as connection:
        connection.sendall(struct.pack("!H", len(query)) + query)
        header = read_exact(connection, 2)
        length = struct.unpack("!H", header)[0]
        if length > 65_535:
            raise ValueError("invalid DNS TCP response length")
        packet = read_exact(connection, length)
    return parse_dns_packet(packet, query_id)


def read_exact(connection: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise ValueError("truncated DNS TCP response")
        data.extend(chunk)
    return bytes(data)


def dns_query(name: str, record_type: str) -> list[str]:
    servers = resolver_addresses()
    if not servers:
        raise RuntimeError("no system DNS resolver is configured")
    query_id, query = make_dns_query(name, DNS_TYPES[record_type])
    errors: list[str] = []
    for server in servers:
        try:
            records, truncated = udp_dns_query(server, query, query_id)
            if truncated:
                records, _ = tcp_dns_query(server, query, query_id)
            return records.get(record_type.lower(), [])
        except (OSError, ValueError, RuntimeError) as exc:
            errors.append(f"{server}: {type(exc).__name__}")
    raise RuntimeError("; ".join(errors[:3]) or "DNS lookup failed")


def dns(domain: str) -> dict[str, Any]:
    if not domain:
        return skipped("DNS record collection requires a domain target")
    result: dict[str, Any] = {"name": domain, "lookup_errors": []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(DNS_TYPES) - 1) as pool:
        futures = {pool.submit(dns_query, domain, record_type): record_type for record_type in DNS_TYPES if record_type != "AXFR"}
        for future in concurrent.futures.as_completed(futures):
            record_type = futures[future]
            try:
                values = future.result()
                key = record_type.lower()
                if record_type == "CNAME":
                    result[key] = values[0] if values else ""
                else:
                    result[key] = values
            except (OSError, ValueError, RuntimeError) as exc:
                result["lookup_errors"].append(f"{record_type}: {safe_error(exc)}")
    for key in ("a", "aaaa", "mx", "ns", "soa", "txt", "srv", "caa", "naptr"):
        result.setdefault(key, [])
    result.setdefault("cname", "")
    result["lookup_errors"] = sorted(result["lookup_errors"])
    return result


def axfr(domain: str, nameservers: list[str]) -> dict[str, Any]:
    if not domain:
        return skipped("AXFR requires a domain target")
    if not nameservers:
        return {"attempted": False, "reason": "no authoritative nameservers returned"}
    attempts: list[dict[str, Any]] = []
    for nameserver in bounded(unique_strings(nameservers), 3):
        try:
            addresses = socket.getaddrinfo(nameserver, 53, type=socket.SOCK_STREAM)
            address = addresses[0][4][0]
            records = axfr_from_server(domain, address)
            attempts.append({"nameserver": nameserver, "status": "transferred", "records": records, "record_count": len(records)})
            break
        except (OSError, ValueError, RuntimeError) as exc:
            attempts.append({"nameserver": nameserver, "status": "refused_or_unavailable", "error": safe_error(exc)})
    return {"attempted": True, "attempts": attempts}


def axfr_from_server(domain: str, server: str) -> list[dict[str, str]]:
    query_id, query = make_dns_query(domain, DNS_TYPES["AXFR"])
    records: list[dict[str, str]] = []
    soa_seen = 0
    received = 0
    with socket.create_connection((server, 53), timeout=TIMEOUT_SECONDS) as connection:
        connection.settimeout(TIMEOUT_SECONDS)
        connection.sendall(struct.pack("!H", len(query)) + query)
        while received < MAX_AXFR_BYTES and len(records) < MAX_AXFR_RECORDS:
            length = struct.unpack("!H", read_exact(connection, 2))[0]
            received += length + 2
            packet = read_exact(connection, length)
            parsed, _ = parse_dns_packet(packet, query_id)
            for record_type, values in parsed.items():
                for value in values:
                    records.append({"type": record_type, "value": safe_text(value, 1024)})
                    if record_type == "soa":
                        soa_seen += 1
                        if soa_seen >= 2:
                            return records
    if received >= MAX_AXFR_BYTES or len(records) >= MAX_AXFR_RECORDS:
        raise RuntimeError("AXFR exceeded bounded transfer limit")
    if not records:
        raise RuntimeError("AXFR returned no records")
    return records


def crtsh(domain: str) -> dict[str, Any]:
    if not domain:
        return skipped("certificate transparency requires a domain target")
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    payload = http_json(url)
    if not isinstance(payload, list):
        raise RuntimeError("unexpected crt.sh response")
    names: set[str] = set()
    for certificate in payload[:10_000]:
        if not isinstance(certificate, dict):
            continue
        for value in str(certificate.get("name_value", "")).splitlines():
            candidate = value.strip().lower().lstrip("*.").rstrip(".")
            if candidate == domain or candidate.endswith("." + domain):
                names.add(candidate)
    ordered = sorted(names)
    return {"subdomains": ordered[:20_000], "certificates_seen": len(payload), "truncated": len(ordered) > 20_000}


def urlscan(domain: str) -> dict[str, Any]:
    key = os.environ.get("RECONX_URLSCAN_KEY", "")
    if not domain:
        return skipped("urlscan requires a domain target")
    if not key:
        return skipped("RECONX_URLSCAN_KEY is not configured")
    payload = http_json(
        "https://urlscan.io/api/v1/search/?" + urllib.parse.urlencode({"q": f"domain:{domain}", "size": "100"}),
        {"API-Key": key},
    )
    entries = payload.get("results", []) if isinstance(payload, dict) else []
    results: list[dict[str, Any]] = []
    for entry in bounded([item for item in entries if isinstance(item, dict)]):
        page = entry.get("page", {}) if isinstance(entry.get("page"), dict) else {}
        task = entry.get("task", {}) if isinstance(entry.get("task"), dict) else {}
        task_uuid = str(task.get("uuid", ""))
        technologies = page.get("technologies", [])
        tech = []
        if isinstance(technologies, list):
            tech = [safe_text(item.get("name", item), 120) if isinstance(item, dict) else safe_text(item, 120) for item in technologies]
        results.append({
            "url": safe_text(page.get("url", ""), 512),
            "ip": safe_text(page.get("ip", ""), 80),
            "technologies": sorted({value for value in tech if value}),
            "screenshot": f"https://urlscan.io/screenshots/{task_uuid}.png" if URLSCAN_UUID_RE.fullmatch(task_uuid) else "",
        })
    return {"scans": len(entries), "results": results}


def download_urlscan_screenshots(urls: list[str], directory: str) -> dict[str, Any]:
    """Persist a small validated historical screenshot set without fetching arbitrary URLs."""
    if not directory:
        return skipped("no screenshot artifact directory was requested")
    os.makedirs(directory, mode=0o750, exist_ok=True)
    results: list[dict[str, str]] = []
    for url in unique_strings(urls)[:20]:
        filename = url.rsplit("/", 1)[-1].removesuffix(".png")
        if not URLSCAN_UUID_RE.fullmatch(filename):
            continue
        try:
            status, content = request_bytes(url, {"Accept": "image/png"})
            if status != 200 or not content.startswith(b"\x89PNG\r\n\x1a\n"):
                results.append({"url": url, "status": f"unavailable_http_{status}"})
                continue
            output = os.path.join(directory, hashlib.sha256(url.encode()).hexdigest()[:16] + ".png")
            temporary = output + ".tmp"
            with open(temporary, "wb") as handle:
                handle.write(content)
            os.chmod(temporary, 0o600)
            os.replace(temporary, output)
            results.append({"url": url, "status": "saved", "path": output})
        except (OSError, RuntimeError, urllib.error.URLError) as exc:
            results.append({"url": url, "status": "error", "error": safe_error(exc)})
    return {"requested": min(len(unique_strings(urls)), 20), "artifacts": results}


def vt_summary(payload: Any) -> dict[str, Any]:
    attributes = payload.get("data", {}).get("attributes", {}) if isinstance(payload, dict) else {}
    if not isinstance(attributes, dict):
        return {}
    return {
        "reputation": attributes.get("reputation"),
        "categories": attributes.get("categories", {}),
        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
        "as_owner": attributes.get("as_owner", ""),
    }


def virustotal(domain: str, ips: list[str]) -> dict[str, Any]:
    key = os.environ.get("RECONX_VT_KEY", "")
    if not key:
        return skipped("RECONX_VT_KEY is not configured")
    headers = {"x-apikey": key}
    result: dict[str, Any] = {"domain": {}, "ips": {}}
    if domain:
        result["domain"] = vt_summary(http_json(f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain, safe='')}", headers))
    for address in ips:
        try:
            result["ips"][address] = vt_summary(http_json(f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(address, safe='')}", headers))
        except (OSError, ValueError, urllib.error.URLError, RuntimeError, json.JSONDecodeError) as exc:
            result["ips"][address] = {"error": safe_error(exc)}
    return result


def shodan_match(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    vulnerabilities = entry.get("vulns", [])
    if isinstance(vulnerabilities, dict):
        vulnerabilities = list(vulnerabilities)
    # Shodan calls this field `data`. Keep a short, redacted copy so the
    # Phase-1 artifact retains the planned banner evidence without persisting
    # credential-like values returned by an Internet-wide scan.
    return {
        "ip": str(entry.get("ip_str", "")),
        "ports": sorted({int(value) for value in entry.get("ports", []) if isinstance(value, int)}),
        "port": entry.get("port"),
        "transport": safe_text(entry.get("transport", ""), 40),
        "product": safe_text(entry.get("product", ""), 160),
        "version": safe_text(entry.get("version", ""), 100),
        "banner": safe_text(entry.get("data", ""), 512),
        "hostnames": bounded(sorted({safe_text(value, 255) for value in entry.get("hostnames", []) if value}), 50),
        "vulnerabilities": bounded(sorted({safe_text(value, 80) for value in vulnerabilities if value}), 50),
        "location": {key: safe_text(value, 120) for key, value in (entry.get("location", {}) or {}).items() if key in {"country_name", "city", "region_code"}},
    }


def shodan(domain: str, ips: list[str]) -> dict[str, Any]:
    key = os.environ.get("RECONX_SHODAN_KEY", "")
    if not key:
        return skipped("RECONX_SHODAN_KEY is not configured")
    result: dict[str, Any] = {"domain": {}, "ips": {}, "neighbors": {}}
    if domain:
        payload = http_json("https://api.shodan.io/shodan/host/search?" + urllib.parse.urlencode({"key": key, "query": f"hostname:{domain}", "minify": "true"}))
        matches = payload.get("matches", []) if isinstance(payload, dict) else []
        result["domain"] = {"total": payload.get("total", 0) if isinstance(payload, dict) else 0, "hosts": bounded([shodan_match(item) for item in matches])}
    networks = sorted({str(ipaddress.ip_network(f"{address}/24", strict=False)) for address in ips if "." in address})[:5]
    for address in ips:
        try:
            payload = http_json("https://api.shodan.io/shodan/host/" + urllib.parse.quote(address, safe="") + "?" + urllib.parse.urlencode({"key": key, "minify": "true"}))
            result["ips"][address] = shodan_match(payload)
        except (OSError, ValueError, urllib.error.URLError, RuntimeError, json.JSONDecodeError) as exc:
            result["ips"][address] = {"error": safe_error(exc)}
    for network in networks:
        try:
            payload = http_json("https://api.shodan.io/shodan/host/search?" + urllib.parse.urlencode({"key": key, "query": f"net:{network}", "minify": "true"}))
            matches = payload.get("matches", []) if isinstance(payload, dict) else []
            result["neighbors"][network] = bounded([shodan_match(item) for item in matches], 50)
        except (OSError, ValueError, urllib.error.URLError, RuntimeError, json.JSONDecodeError) as exc:
            result["neighbors"][network] = {"error": safe_error(exc)}
    return result


def censys_headers() -> dict[str, str] | None:
    api_id, secret = os.environ.get("RECONX_CENSYS_ID", ""), os.environ.get("RECONX_CENSYS_SECRET", "")
    bearer = os.environ.get("RECONX_CENSYS_KEY", "")
    if api_id and secret:
        token = base64.b64encode(f"{api_id}:{secret}".encode()).decode()
        return {"Authorization": f"Basic {token}"}
    if bearer:
        return {"Authorization": f"Bearer {bearer}"}
    return None


def censys_hit(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    services = entry.get("services", [])
    summarized_services: list[dict[str, Any]] = []
    certificates: list[str] = [safe_text(value, 255) for value in entry.get("names", []) if value]
    if isinstance(services, list):
        for service in services[:50]:
            if not isinstance(service, dict):
                continue
            summarized_services.append({key: safe_text(service.get(key, ""), 160) for key in ("port", "service_name", "transport", "software", "extended_service_name") if service.get(key, "") != ""})
            tls = service.get("tls", {}) if isinstance(service.get("tls"), dict) else {}
            certificate = tls.get("certificates", {}) if isinstance(tls.get("certificates"), dict) else {}
            leaf = certificate.get("leaf_data", {}) if isinstance(certificate.get("leaf_data"), dict) else {}
            certificates.extend(safe_text(value, 255) for value in leaf.get("names", []) if value)
    asn = entry.get("autonomous_system", {}) if isinstance(entry.get("autonomous_system"), dict) else {}
    return {
        "ip": safe_text(entry.get("ip", entry.get("ip_address", "")), 80),
        "services": summarized_services,
        "tags": bounded(sorted({safe_text(value, 80) for value in entry.get("labels", entry.get("tags", [])) if value}), 50),
        "certificates": bounded(sorted(set(certificates)), 50),
        "asn": {key: safe_text(value, 120) for key, value in asn.items() if key in {"asn", "name", "description", "country_code"}},
    }


def censys_search(query: str, headers: dict[str, str]) -> list[dict[str, Any]]:
    payload = http_json("https://search.censys.io/api/v2/hosts/search?" + urllib.parse.urlencode({"q": query, "per_page": "50", "fields": "ip,services,labels,autonomous_system,services.tls.certificates.leaf_data.names"}), headers)
    result = payload.get("result", payload) if isinstance(payload, dict) else {}
    hits = result.get("hits", []) if isinstance(result, dict) else []
    return bounded([censys_hit(item) for item in hits if isinstance(item, dict)], 50)


def censys(domain: str, ips: list[str]) -> dict[str, Any]:
    headers = censys_headers()
    if headers is None:
        return skipped("RECONX_CENSYS_KEY or RECONX_CENSYS_ID/RECONX_CENSYS_SECRET is not configured")
    result: dict[str, Any] = {"domain": [], "ips": {}, "neighbors": {}}
    if domain:
        result["domain"] = censys_search(f"services.tls.certificates.leaf_data.names: {domain}", headers)
    for address in ips:
        try:
            result["ips"][address] = censys_search(f"ip: {address}", headers)
        except (OSError, ValueError, urllib.error.URLError, RuntimeError, json.JSONDecodeError) as exc:
            result["ips"][address] = {"error": safe_error(exc)}
    for network in sorted({str(ipaddress.ip_network(f"{address}/24", strict=False)) for address in ips if "." in address})[:5]:
        try:
            result["neighbors"][network] = censys_search(f"ip: {network}", headers)
        except (OSError, ValueError, urllib.error.URLError, RuntimeError, json.JSONDecodeError) as exc:
            result["neighbors"][network] = {"error": safe_error(exc)}
    return result


def github_code_search(domain: str, ips: list[str], emails: list[str] | None = None) -> dict[str, Any]:
    token = os.environ.get("RECONX_GITHUB_TOKEN", "")
    if not token:
        return skipped("RECONX_GITHUB_TOKEN is not configured")
    terms = ([domain] if domain else []) + ips[:5] + (emails or [])[:5]
    result: dict[str, Any] = {"queries": [], "potential_secret_indicators": [], "emails": []}
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.text-match+json"}
    for term in unique_strings(terms)[:10]:
        payload = http_json("https://api.github.com/search/code?" + urllib.parse.urlencode({"q": f'"{term}"', "per_page": "100"}), headers)
        items = payload.get("items", []) if isinstance(payload, dict) else []
        matches: list[dict[str, str]] = []
        for item in bounded([entry for entry in items if isinstance(entry, dict)]):
            repository = item.get("repository", {}) if isinstance(item.get("repository"), dict) else {}
            match = {"repository": safe_text(repository.get("full_name", ""), 200), "path": safe_text(item.get("path", ""), 300), "url": safe_text(item.get("html_url", ""), 512)}
            matches.append(match)
            fragments = [str(value.get("fragment", "")) for value in item.get("text_matches", []) if isinstance(value, dict)]
            for fragment in fragments:
                result["emails"].extend(EMAIL_RE.findall(fragment))
            if any(SECRET_LABEL_RE.search(fragment) for fragment in fragments):
                result["potential_secret_indicators"].append({"source": "github_code_search", "repository": match["repository"], "path": match["path"], "indicator": "credential-like assignment in public code search result"})
        result["queries"].append({"term": term, "total": payload.get("total_count", 0) if isinstance(payload, dict) else 0, "matches": matches})
    result["emails"] = unique_strings(result["emails"])[:50]
    return result


def gitlab_code_search(domain: str, ips: list[str], emails: list[str] | None = None) -> dict[str, Any]:
    token = os.environ.get("RECONX_GITLAB_TOKEN", "")
    if not token:
        return skipped("RECONX_GITLAB_TOKEN is not configured")
    terms = ([domain] if domain else []) + ips[:5] + (emails or [])[:5]
    headers = {"PRIVATE-TOKEN": token}
    result: dict[str, Any] = {"queries": [], "potential_secret_indicators": [], "emails": []}
    for term in unique_strings(terms)[:10]:
        payload = http_json("https://gitlab.com/api/v4/search?" + urllib.parse.urlencode({"scope": "blobs", "search": term, "per_page": "100"}), headers)
        matches: list[dict[str, str]] = []
        if isinstance(payload, list):
            for item in bounded([entry for entry in payload if isinstance(entry, dict)]):
                project = safe_text(item.get("project_id", ""), 80)
                path = safe_text(item.get("path", item.get("filename", "")), 300)
                matches.append({"project": project, "path": path, "url": safe_text(item.get("url", ""), 512)})
                # GitLab's blob-search `data` is a short public match excerpt.
                # Inspect it only in memory, retain emails and redacted
                # indicators, and never write the excerpt to the artifact.
                excerpt = str(item.get("data", ""))
                result["emails"].extend(EMAIL_RE.findall(excerpt))
                if SECRET_LABEL_RE.search(excerpt):
                    result["potential_secret_indicators"].append({"source": "gitlab_code_search", "repository": f"gitlab-project:{project}", "path": path, "indicator": "credential-like assignment in public code search result"})
        result["queries"].append({"term": term, "matches": matches})
    result["emails"] = unique_strings(result["emails"])[:50]
    return result


def dorks(domain: str) -> dict[str, Any]:
    if not domain:
        return skipped("search dorks require a domain target")
    return {"queries": [
        f"site:{domain} inurl:admin",
        f"site:{domain} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:zip OR filetype:sql OR filetype:bak",
        f"site:{domain} intitle:\"index of\"",
        f"site:{domain} inurl:php?",
        f"\"{domain}\" password OR passwd OR credential",
        f"\"{domain}\" api_key OR secret OR token",
    ], "public_index_queries": [
        f"site:pastebin.com \"{domain}\"",
        f"site:gitlab.com \"{domain}\"",
        f"site:bitbucket.org \"{domain}\"",
        f"site:linkedin.com/in \"{domain}\"",
        f"site:linkedin.com/company \"{domain}\"",
    ]}


def linkedin_employee_lead(title: str, url: str, snippet: str) -> dict[str, str]:
    """Normalize a public LinkedIn search hit without scraping LinkedIn pages.

    Search results are the available public, low-volume source. The title is
    retained as a lead rather than asserting employment as fact.
    """
    parts = [part.strip() for part in re.split(r"\s+[|–-]\s+", title) if part.strip()]
    name = parts[0] if parts else title
    if name.lower().endswith("linkedin") and len(parts) > 1:
        name = parts[1]
    return {
        "name": safe_text(name.removesuffix(" | LinkedIn"), 160),
        "headline": safe_text(" — ".join(parts[1:]) or snippet, 320),
        "url": safe_text(url, 512),
        "source": "public_search_result",
    }


def serpapi(domain: str, ips: list[str] | None = None, emails: list[str] | None = None, *, include_dorks: bool = True) -> dict[str, Any]:
    key = os.environ.get("RECONX_SERP_KEY", "")
    terms = ([domain] if domain else []) + (ips or [])[:3] + (emails or [])[:3]
    if not terms:
        return skipped("no domain, IP, or public email search terms are available")
    if not key:
        return skipped("RECONX_SERP_KEY is not configured; dorks are still provided for manual review")
    manual = dorks(domain).get("queries", []) if domain and include_dorks else []
    quoted_terms = " OR ".join(f'"{term}"' for term in unique_strings(terms))
    query_specs = [("dork", query) for query in manual] + [
        ("pastebin", f"site:pastebin.com ({quoted_terms})"),
        ("gitlab_public_index", f"site:gitlab.com ({quoted_terms})"),
        ("bitbucket_public_index", f"site:bitbucket.org ({quoted_terms})"),
        ("linkedin_people", f"site:linkedin.com/in ({quoted_terms})"),
        ("linkedin_company", f"site:linkedin.com/company ({quoted_terms})"),
    ]
    cap = min(MAX_SEARCH_QUERIES, max(1, int(os.environ.get("RECONX_OSINT_MAX_SEARCH_QUERIES", str(MAX_SEARCH_QUERIES)))))
    results: list[dict[str, Any]] = []
    discovered_emails: list[str] = []
    employees: list[dict[str, str]] = []
    potential_secret_indicators: list[dict[str, str]] = []
    for category, query in query_specs[:cap]:
        payload = http_json("https://serpapi.com/search.json?" + urllib.parse.urlencode({"engine": "google", "q": query, "api_key": key, "num": "10"}))
        organic = payload.get("organic_results", []) if isinstance(payload, dict) else []
        normalized_results: list[dict[str, str]] = []
        for item in bounded([entry for entry in organic if isinstance(entry, dict)], 10):
            title, url, snippet = str(item.get("title", "")), str(item.get("link", "")), str(item.get("snippet", ""))
            discovered_emails.extend(EMAIL_RE.findall(" ".join((title, snippet))))
            normalized_results.append({"title": safe_text(title, 240), "url": safe_text(url, 512), "snippet": safe_text(snippet, 320)})
            if SECRET_LABEL_RE.search(" ".join((title, snippet))):
                potential_secret_indicators.append({
                    "source": f"{category}_public_index",
                    "path": safe_text(url, 512),
                    "indicator": "credential-like language in public search result",
                })
            if category == "linkedin_people" and "linkedin.com/in/" in url.lower():
                employees.append(linkedin_employee_lead(title, url, snippet))
        results.append({"category": category, "query": query, "results": normalized_results})
    employee_by_url = {employee["url"]: employee for employee in employees if employee.get("url")}
    return {
        "queries_executed": len(results),
        "results": results,
        "emails": unique_strings(discovered_emails)[:50],
        "employees": [employee_by_url[url] for url in sorted(employee_by_url)][:100],
        "potential_secret_indicators": potential_secret_indicators[:100],
    }


def securitytrails(domain: str) -> dict[str, Any]:
    key = os.environ.get("RECONX_SECURITYTRAILS_KEY", "")
    if not domain:
        return skipped("SecurityTrails history requires a domain target")
    if not key:
        return skipped("RECONX_SECURITYTRAILS_KEY is not configured")
    payload = http_json(f"https://api.securitytrails.com/v1/history/{urllib.parse.quote(domain, safe='')}/dns/a", {"APIKEY": key})
    records = payload.get("records", []) if isinstance(payload, dict) else []
    return {"history_count": len(records), "records": bounded([safe_text(entry, 1024) for entry in records if entry], 100)}


def viewdns(domain: str, ips: list[str]) -> dict[str, Any]:
    key = os.environ.get("RECONX_VIEWDNS_KEY", "")
    if not key:
        return skipped("RECONX_VIEWDNS_KEY is not configured")
    result: dict[str, Any] = {"dns_history": {}, "reverse_ip": {}}
    if domain:
        payload = http_json("https://api.viewdns.info/iphistory/?" + urllib.parse.urlencode({"domain": domain, "output": "json", "apikey": key}))
        result["dns_history"] = payload if isinstance(payload, dict) else {}
    for address in ips:
        try:
            payload = http_json("https://api.viewdns.info/reverseip/?" + urllib.parse.urlencode({"host": address, "output": "json", "apikey": key}))
            result["reverse_ip"][address] = payload if isinstance(payload, dict) else {}
        except (OSError, ValueError, urllib.error.URLError, RuntimeError, json.JSONDecodeError) as exc:
            result["reverse_ip"][address] = {"error": safe_error(exc)}
    return result


def network_ownership(ips: list[str]) -> dict[str, Any]:
    if not ips:
        return skipped("no global target IP addresses are available")
    token = os.environ.get("RECONX_IPINFO_TOKEN", "")
    headers = {"Authorization": f"Bearer {token}"} if token else None
    result: dict[str, Any] = {}
    for address in ips:
        entry: dict[str, Any] = {}
        try:
            info = http_json(f"https://ipinfo.io/{urllib.parse.quote(address, safe='')}/json", headers)
            if isinstance(info, dict):
                entry["ipinfo"] = {key: safe_text(info.get(key, ""), 256) for key in ("ip", "hostname", "city", "region", "country", "org", "postal", "timezone", "asn", "company") if info.get(key, "") != ""}
        except (OSError, ValueError, urllib.error.URLError, RuntimeError, json.JSONDecodeError) as exc:
            entry["ipinfo_error"] = safe_error(exc)
        try:
            bgp = http_json(f"https://api.bgp.tools/api/v1/lookup/{urllib.parse.quote(address, safe='')}")
            entry["bgp_tools"] = bgp if isinstance(bgp, dict) else {}
        except (OSError, ValueError, urllib.error.URLError, RuntimeError, json.JSONDecodeError) as exc:
            entry["bgp_tools_error"] = safe_error(exc)
        result[address] = entry
    return result


def hibp(emails: list[str]) -> dict[str, Any]:
    key = os.environ.get("RECONX_HIBP_KEY", "")
    if not key:
        return skipped("RECONX_HIBP_KEY is not configured")
    if not emails:
        return skipped("no public email addresses were discovered")
    result: dict[str, Any] = {}
    headers = {"hibp-api-key": key, "User-Agent": USER_AGENT}
    for index, email in enumerate(unique_strings(emails)[:20]):
        if index:
            time.sleep(1.6)  # HIBP's documented request cadence.
        status, data = request_bytes("https://haveibeenpwned.com/api/v3/breachedaccount/" + urllib.parse.quote(email, safe="") + "?truncateResponse=true", headers)
        if status == 404:
            result[email] = {"status": "not_pwned"}
            continue
        if status != 200:
            result[email] = {"status": "error", "error": f"HTTP {status}"}
            continue
        payload = json.loads(data.decode("utf-8", errors="replace"))
        breaches = []
        if isinstance(payload, list):
            breaches = [{key: safe_text(item.get(key, ""), 200) for key in ("Name", "Domain", "BreachDate") if item.get(key, "") != ""} for item in payload if isinstance(item, dict)]
        result[email] = {"status": "pwned" if breaches else "not_pwned", "breaches": breaches}
    return result


def social_enum(emails: list[str]) -> dict[str, Any]:
    executable = os.environ.get("RECONX_SHERLOCK_PATH", "") or shutil.which("sherlock") or ""
    if not executable:
        return skipped("sherlock is not installed or configured")
    usernames = sorted({email.split("@", 1)[0] for email in emails if "@" in email and 2 <= len(email.split("@", 1)[0]) <= 32})[:5]
    if not usernames:
        return skipped("no suitable public email local-parts were discovered")
    try:
        completed = subprocess.run([executable, *usernames, "--print-found", "--no-color", "--timeout", "5"], capture_output=True, text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": safe_error(exc)}
    urls = sorted({line.strip() for line in completed.stdout.splitlines() if line.strip().startswith(("http://", "https://"))})
    return {"usernames": usernames, "profiles": bounded(urls, 500), "exit_code": completed.returncode}


def run_source(name: str, function: Callable[[], dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    started = datetime.now(timezone.utc)
    try:
        data = function()
        status = "skipped" if isinstance(data, dict) and "skipped" in data else "disabled" if isinstance(data, dict) and "disabled" in data else "ok"
        return name, {"status": status, "duration_ms": int((datetime.now(timezone.utc) - started).total_seconds() * 1000), "data": data}
    except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError, RuntimeError, json.JSONDecodeError, struct.error) as exc:
        return name, {"status": "error", "duration_ms": int((datetime.now(timezone.utc) - started).total_seconds() * 1000), "error": safe_error(exc)}


def safe_error(exc: BaseException) -> str:
    """Return diagnosable source errors without reflecting URLs or API keys."""
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return f"network error: {type(exc.reason).__name__}"
    return f"{type(exc).__name__}: {str(exc)[:300]}"


def source_data(sources: dict[str, dict[str, Any]], name: str) -> dict[str, Any]:
    data = sources.get(name, {}).get("data", {})
    return data if isinstance(data, dict) else {}


def resolve(target: str, supplied_ips: list[str] | None = None, *, attempt_axfr: bool = False, enable_social_enum: bool = False, screenshot_dir: str = "") -> dict[str, Any]:
    value = target.strip().lower().rstrip(".")
    domain = ""
    ips = list(supplied_ips or [])
    try:
        address = ipaddress.ip_address(value)
        ips.append(str(address))
        value = str(address)
    except ValueError:
        domain = clean_domain(value)
    ips = public_ips(ips)

    jobs: dict[str, Callable[[], dict[str, Any]]] = {
        "dns": lambda: dns(domain),
        "whois": lambda: whois(domain),
        "certificate_transparency": lambda: crtsh(domain),
        "urlscan": lambda: urlscan(domain),
        "virustotal": lambda: virustotal(domain, ips),
        "shodan": lambda: shodan(domain, ips),
        "censys": lambda: censys(domain, ips),
        "github_code_search": lambda: github_code_search(domain, ips),
        "gitlab_code_search": lambda: gitlab_code_search(domain, ips),
        "search_engine_recon": lambda: serpapi(domain, ips),
        "securitytrails_dns_history": lambda: securitytrails(domain),
        "viewdns_history_and_reverse_ip": lambda: viewdns(domain, ips),
        "network_ownership": lambda: network_ownership(ips),
        "dorks": lambda: dorks(domain),
    }
    sources: dict[str, dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(jobs))) as pool:
        futures = [pool.submit(run_source, name, function) for name, function in jobs.items()]
        for future in concurrent.futures.as_completed(futures):
            name, result = future.result()
            sources[name] = result

    dns_data = source_data(sources, "dns")
    ips = public_ips(ips + list(dns_data.get("a", [])) + list(dns_data.get("aaaa", [])))
    whois_data = source_data(sources, "whois")
    # Public code-search fragments and search snippets are processed only in
    # memory by their source adapters. The worker retains discovered email
    # addresses, not raw snippets, so HIBP covers every bounded public email
    # lead without persisting credential-like search content.
    email_sources = ("github_code_search", "gitlab_code_search", "search_engine_recon")
    emails = unique_strings(
        list(whois_data.get("emails", []))
        + [email for name in email_sources for email in source_data(sources, name).get("emails", []) if isinstance(email, str)]
    )[:50]

    # Search the first bounded email set concurrently with AXFR, then collect
    # the second-hop public email leads before HIBP/Sherlock run. This ensures
    # HIBP receives every email the worker discovered, not just WHOIS data.
    dependent: dict[str, Callable[[], dict[str, Any]]] = {
        "dns_zone_transfer": lambda: axfr(domain, list(dns_data.get("ns", []))) if attempt_axfr else disabled("enable --axfr for bounded authoritative-server AXFR attempts"),
        "github_code_search_discovered_emails": lambda: github_code_search("", [], emails),
        "gitlab_code_search_discovered_emails": lambda: gitlab_code_search("", [], emails),
        "search_engine_recon_discovered_emails": lambda: serpapi("", [], emails, include_dorks=False),
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(dependent)) as pool:
        futures = [pool.submit(run_source, name, function) for name, function in dependent.items()]
        for future in concurrent.futures.as_completed(futures):
            name, result = future.result()
            sources[name] = result
    all_email_sources = email_sources + (
        "github_code_search_discovered_emails",
        "gitlab_code_search_discovered_emails",
        "search_engine_recon_discovered_emails",
    )
    emails = unique_strings(
        list(whois_data.get("emails", []))
        + [email for name in all_email_sources for email in source_data(sources, name).get("emails", []) if isinstance(email, str)]
    )[:50]
    final_email_jobs: dict[str, Callable[[], dict[str, Any]]] = {
        "hibp": lambda: hibp(emails),
        "social_username_enumeration": lambda: social_enum(emails) if enable_social_enum else disabled("enable --social-enum to invoke sherlock"),
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(final_email_jobs)) as pool:
        futures = [pool.submit(run_source, name, function) for name, function in final_email_jobs.items()]
        for future in concurrent.futures.as_completed(futures):
            name, result = future.result()
            sources[name] = result

    ct_data = source_data(sources, "certificate_transparency")
    subdomains = unique_strings(list(ct_data.get("subdomains", [])))[:20_000]
    urlscan_data = source_data(sources, "urlscan")
    scan_results = urlscan_data.get("results", []) if isinstance(urlscan_data.get("results"), list) else []
    tech_stack: list[str] = []
    screenshots: list[str] = []
    for item in scan_results:
        if not isinstance(item, dict):
            continue
        tech_stack.extend(value for value in item.get("technologies", []) if isinstance(value, str))
        if isinstance(item.get("screenshot"), str) and item["screenshot"]:
            screenshots.append(item["screenshot"])
    if screenshot_dir:
        source_name, source_result = run_source("urlscan_screenshot_downloads", lambda: download_urlscan_screenshots(screenshots, screenshot_dir))
        sources[source_name] = source_result
    shodan_data = source_data(sources, "shodan")
    shodan_entries = list(shodan_data.get("domain", {}).get("hosts", [])) if isinstance(shodan_data.get("domain"), dict) else []
    shodan_entries.extend(value for value in shodan_data.get("ips", {}).values() if isinstance(value, dict))
    for item in shodan_entries:
        product = item.get("product", "") if isinstance(item, dict) else ""
        version = item.get("version", "") if isinstance(item, dict) else ""
        if isinstance(product, str) and product:
            tech_stack.append((product + " " + version).strip() if isinstance(version, str) else product)
    censys_data = source_data(sources, "censys")
    censys_hits = list(censys_data.get("domain", [])) if isinstance(censys_data.get("domain"), list) else []
    for values in censys_data.get("ips", {}).values() if isinstance(censys_data.get("ips"), dict) else []:
        if isinstance(values, list):
            censys_hits.extend(values)
    for hit in censys_hits:
        if not isinstance(hit, dict):
            continue
        for service in hit.get("services", []):
            if isinstance(service, dict) and isinstance(service.get("software"), str) and service["software"]:
                tech_stack.append(service["software"])
    secret_indicators: list[dict[str, str]] = []
    for name in (
        "github_code_search",
        "github_code_search_discovered_emails",
        "gitlab_code_search",
        "gitlab_code_search_discovered_emails",
        "search_engine_recon",
        "search_engine_recon_discovered_emails",
    ):
        for item in source_data(sources, name).get("potential_secret_indicators", []):
            if isinstance(item, dict):
                secret_indicators.append({key: safe_text(item.get(key, ""), 300) for key in ("source", "repository", "path", "indicator") if item.get(key, "")})
    employee_leads = source_data(sources, "search_engine_recon").get("employees", [])
    employees = [item for item in employee_leads if isinstance(item, dict)][:100]

    return {
        "target": value,
        "dns": dns_data if domain else {"name": value, "a": [], "aaaa": [], "lookup_errors": []},
        "whois": whois_data,
        "subdomains": subdomains,
        "emails": emails,
        "dorks": source_data(sources, "dorks").get("queries", []),
        "employees": employees,
        "tech_stack": unique_strings(tech_stack),
        "screenshots": unique_strings(screenshots),
        "secret_indicators": secret_indicators,
        "sources": dict(sorted(sources.items())),
        "warnings": [f"{name}: {value.get('error', source_data({name: value}, name).get('skipped', 'unknown error'))}" for name, value in sorted(sources.items()) if value.get("status") in {"error", "skipped"}],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="reconx bounded passive OSINT worker")
    parser.add_argument("--target", required=True, help="domain or IP target")
    parser.add_argument("--ip", action="append", default=[], help="resolved target IP address (repeatable)")
    parser.add_argument("--axfr", action="store_true", help="attempt bounded AXFR against discovered authoritative nameservers")
    parser.add_argument("--social-enum", action="store_true", help="invoke configured sherlock with discovered public email local-parts")
    parser.add_argument("--screenshot-dir", default="", help="owner-controlled directory for bounded urlscan PNG artifacts")
    arguments = parser.parse_args()
    print(json.dumps(resolve(arguments.target, arguments.ip, attempt_axfr=arguments.axfr, enable_social_enum=arguments.social_enum, screenshot_dir=arguments.screenshot_dir), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

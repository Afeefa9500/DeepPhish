"""Optional read-only domain intelligence checks. Never fetches page content."""
from __future__ import annotations
import ipaddress, socket, ssl, time
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

TIMEOUT = 4
USER_AGENT = "DeepPhish-URL-Guard/2.0 (educational security checker)"

def _get_json(url, params=None):
    try:
        response = requests.get(url, params=params, timeout=TIMEOUT,
                                headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        if response.status_code == 200:
            return response.json(), None
        return None, f"Service returned HTTP {response.status_code}"
    except requests.RequestException as exc:
        return None, str(exc)

def resolve_public_ips(hostname):
    """Resolve with DNS-over-HTTPS and reject private, loopback, link-local and reserved IPs."""
    answers = []
    errors = []
    for qtype in ("A", "AAAA"):
        data, err = _get_json("https://cloudflare-dns.com/dns-query",
                              params={"name": hostname, "type": qtype})
        if err:
            errors.append(err)
            continue
        for answer in data.get("Answer", []):
            value = answer.get("data", "").strip()
            try:
                ip = ipaddress.ip_address(value)
                if ip.is_global:
                    answers.append(str(ip))
            except ValueError:
                continue
    return sorted(set(answers)), ("; ".join(errors) if errors and not answers else None)

def domain_rdap(hostname):
    # IP literals and local names do not have public domain registration records.
    try:
        ipaddress.ip_address(hostname)
        return None, "Host is an IP address; RDAP domain lookup is not applicable."
    except ValueError:
        pass
    if "." not in hostname or hostname == "localhost":
        return None, "Not a public registrable domain."
    data, err = _get_json(f"https://rdap.org/domain/{hostname}")
    if err:
        return None, err
    created = None
    registrar = None
    status = data.get("status", [])
    for event in data.get("events", []):
        if event.get("eventAction", "").lower() in {"registration", "registered"}:
            created = event.get("eventDate")
            break
    entities = data.get("entities", [])
    for entity in entities:
        if "registrar" in [r.lower() for r in entity.get("roles", [])]:
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] == "fn" and len(item) > 3:
                        registrar = item[3]
                        break
    age_days = None
    if created:
        try:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age_days = max(0, (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).days)
        except Exception:
            pass
    return {"created": created, "age_days": age_days, "registrar": registrar,
            "statuses": status[:8], "rdap_name": data.get("ldhName") or data.get("name")}, None

def tls_certificate(hostname, port=443):
    """Inspect TLS handshake only, after resolving to a globally routable IP."""
    ips, err = resolve_public_ips(hostname)
    if not ips:
        return None, err or "No public IP address found; TLS check skipped."
    ip = ips[0]
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                not_after = cert.get("notAfter")
                expiry = None
                days_left = None
                if not_after:
                    expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    expiry = expiry_dt.isoformat()
                    days_left = (expiry_dt - datetime.now(timezone.utc)).days
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                return {
                    "hostname_match": True, "tls_version": tls_sock.version(),
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "subject": subject.get("commonName"), "expires_at": expiry,
                    "days_until_expiry": days_left,
                }, None
    except Exception as exc:
        return None, f"TLS handshake failed: {exc}"

def investigate_domain(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    result = {"host": host, "scheme": parsed.scheme, "port": parsed.port or (443 if parsed.scheme == "https" else 80),
              "checked_at": datetime.now(timezone.utc).isoformat(), "dns": None, "rdap": None, "tls": None,
              "notes": []}
    ips, dns_error = resolve_public_ips(host) if not is_ip else ([], "Host is an IP literal.")
    result["dns"] = {"public_ip_addresses": ips} if ips else None
    if dns_error:
        result["notes"].append("DNS: " + dns_error)
    rdap, rdap_error = domain_rdap(host)
    result["rdap"] = rdap
    if rdap_error:
        result["notes"].append("Registration: " + rdap_error)
    if parsed.scheme == "https" and not is_ip:
        tls, tls_error = tls_certificate(host)
        result["tls"] = tls
        if tls_error:
            result["notes"].append("TLS: " + tls_error)
    else:
        result["notes"].append("TLS certificate check is available for HTTPS domain URLs only.")
    return result

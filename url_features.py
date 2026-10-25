
"""Shared URL-only feature extraction for training and inference."""

from __future__ import annotations

from urllib.parse import urlparse, unquote, urlunparse
import ipaddress
import re
from collections import Counter


SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rebrand.ly",
    "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in", "s.id", "v.gd",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "gq", "tk", "work", "click",
    "rest", "fit", "support", "kim", "party", "loan", "cf", "ml",
}

PHISH_HINTS = {
    "account", "activity", "auth", "bank", "billing", "confirm",
    "credential", "free", "gift", "login", "log-in", "signin",
    "sign-in", "secure", "security", "update", "verify",
    "verification", "wallet", "password", "recover", "webscr",
    "payment", "invoice", "unlock", "limited", "suspended",
}

WORD_RE = re.compile(r"[a-zA-Z0-9]+")

FEATURE_NAMES = [
    "length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens",
    "nb_at", "nb_qm", "nb_and", "nb_or", "nb_eq", "nb_underscore",
    "nb_tilde", "nb_percent", "nb_slash", "nb_star", "nb_colon",
    "nb_comma", "nb_semicolumn", "nb_dollar", "nb_space", "nb_www",
    "nb_com", "nb_dslash", "http_in_path", "https_token",
    "ratio_digits_url", "ratio_digits_host", "punycode", "port",
    "tld_in_path", "tld_in_subdomain", "abnormal_subdomain",
    "nb_subdomains", "prefix_suffix", "shortening_service",
    "path_extension", "length_words_raw", "char_repeat",
    "shortest_words_raw", "shortest_word_host", "shortest_word_path",
    "longest_words_raw", "longest_word_host", "longest_word_path",
    "avg_words_raw", "avg_word_host", "avg_word_path", "phish_hints",
    "suspecious_tld", "statistical_report",
]


def parse_url(raw: str):
    raw = str(raw).strip()

    if not raw:
        raise ValueError("Enter a URL.")

    if len(raw) > 4096:
        raise ValueError("URL is too long (maximum 4096 characters).")

    if any(ord(char) < 32 for char in raw):
        raise ValueError("URL contains control characters.")

    candidate = (
        raw
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw)
        else "https://" + raw
    )

    parsed = urlparse(candidate)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Enter a full domain or URL, e.g. example.com.")

    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("The domain name could not be parsed.") from exc

    if not hostname or ("." not in hostname and hostname != "localhost"):
        raise ValueError("Enter a full domain name, such as example.com.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc

    # Preserve credentials in the parsed object for analysis, but remove
    # them from the normalized URL used for model inference.
    netloc = hostname
    if port is not None:
        netloc += f":{port}"

    normalized = urlunparse((
        parsed.scheme.lower(),
        netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        "",
    ))

    return normalized, parsed, hostname


def extract_features(raw: str) -> dict:
    normalized, parsed, hostname = parse_url(raw)

    # Keep the original input for indicators that normalization can erase,
    # particularly '@' in credential-style URLs.
    original = str(raw).strip()
    lower = unquote(normalized).lower()
    original_lower = unquote(original).lower()

    host = hostname
    path = parsed.path or ""
    path_query = path + ("?" + parsed.query if parsed.query else "")

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        is_ip = 1
    except ValueError:
        is_ip = 0

    labels = [part for part in host.split(".") if part]
    suffix = labels[-1] if labels else ""

    host_words = WORD_RE.findall(host)
    path_words = WORD_RE.findall(path_query)
    all_words = WORD_RE.findall(lower)

    repeated = sum(max(0, count - 1) for count in Counter(lower).values())
    digits_url = sum(char.isdigit() for char in lower)
    digits_host = sum(char.isdigit() for char in host)

    shortening = int(
        host in SHORTENERS
        or any(host.endswith("." + domain) for domain in SHORTENERS)
    )

    tld_in_path = int(
        any("." + tld in path.lower()
            for tld in ("com", "net", "org", "ru", "cn", "co"))
    )

    tld_in_subdomain = int(
        len(labels) > 2
        and any(part in {"com", "net", "org", "co", "gov", "edu"}
                for part in labels[:-2])
    )

    suspicious_words = sum(1 for word in PHISH_HINTS if word in lower)
    port_flag = int(parsed.port is not None)
    path_extension = int(bool(re.search(r"\.[a-zA-Z0-9]{1,8}$", path)))

    features = {
        "length_url": len(normalized),
        "length_hostname": len(host),
        "ip": is_ip,
        "nb_dots": lower.count("."),
        "nb_hyphens": lower.count("-"),
        "nb_at": original_lower.count("@"),
        "nb_qm": lower.count("?"),
        "nb_and": lower.count("&"),
        "nb_or": lower.count("|"),
        "nb_eq": lower.count("="),
        "nb_underscore": lower.count("_"),
        "nb_tilde": lower.count("~"),
        "nb_percent": lower.count("%"),
        "nb_slash": lower.count("/"),
        "nb_star": lower.count("*"),
        "nb_colon": lower.count(":"),
        "nb_comma": lower.count(","),
        "nb_semicolumn": lower.count(";"),
        "nb_dollar": lower.count("$"),
        "nb_space": original.count(" "),
        "nb_www": lower.count("www"),
        "nb_com": lower.count("com"),
        "nb_dslash": lower.count("//"),
        "http_in_path": int("http" in path.lower()),
        "https_token": int("https" in (path + parsed.query).lower()),
        "ratio_digits_url": digits_url / max(1, len(lower)),
        "ratio_digits_host": digits_host / max(1, len(host)),
        "punycode": int("xn--" in host),
        "port": port_flag,
        "tld_in_path": tld_in_path,
        "tld_in_subdomain": tld_in_subdomain,
        "abnormal_subdomain": int(len(labels) > 4),
        "nb_subdomains": max(0, len(labels) - 1),
        "prefix_suffix": int("-" in host),
        "shortening_service": shortening,
        "path_extension": path_extension,
        "length_words_raw": len(all_words),
        "char_repeat": repeated,
        "shortest_words_raw": min((len(word) for word in all_words), default=0),
        "shortest_word_host": min((len(word) for word in host_words), default=0),
        "shortest_word_path": min((len(word) for word in path_words), default=0),
        "longest_words_raw": max((len(word) for word in all_words), default=0),
        "longest_word_host": max((len(word) for word in host_words), default=0),
        "longest_word_path": max((len(word) for word in path_words), default=0),
        "avg_words_raw": sum(map(len, all_words)) / max(1, len(all_words)),
        "avg_word_host": sum(map(len, host_words)) / max(1, len(host_words)),
        "avg_word_path": sum(map(len, path_words)) / max(1, len(path_words)),
        "phish_hints": suspicious_words,
        "suspecious_tld": int(suffix in SUSPICIOUS_TLDS),
        "statistical_report": int(is_ip or shortening or suspicious_words >= 2),
    }

    return {name: features[name] for name in FEATURE_NAMES}


def normalize_url(raw: str) -> str:
    return parse_url(raw)[0]

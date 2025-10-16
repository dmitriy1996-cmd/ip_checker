from __future__ import annotations
import requests
from typing import Dict, Optional, Tuple, Any

def parse_proxy_line(line: str, default_scheme: str = "http") -> Optional[str]:
    s = (line or "").strip()
    if not s:
        return None
    if "://" in s:
        return s
    parts = s.split(":")
    if len(parts) == 2:
        host, port = parts
        return f"{default_scheme}://{host}:{port}"
    if len(parts) == 4:
        host, port, user, pwd = parts
        return f"{default_scheme}://{user}:{pwd}@{host}:{port}"
    return None

def http_get_json(session: requests.Session, url: str, timeout: int = 8, retries: int = 1, proxies: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    last = None
    for _ in range(retries + 1):
        try:
            r = session.get(url, timeout=timeout, proxies=proxies)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            last = e
    raise last if last else RuntimeError("network error")

def resolve_exit_ip(proxy_url: str, timeout: float = 8.0) -> Tuple[Optional[str], Dict[str, Any]]:
    sess = requests.Session()
    p = {"http": proxy_url, "https": proxy_url}
    try:
        d = http_get_json(sess, "http://ip-api.com/json", timeout=int(timeout), retries=1, proxies=p)
        ip = d.get("query")
        meta = {"country": d.get("country"), "region": d.get("regionName"), "city": d.get("city")}
        if ip:
            return ip, meta
    except Exception:
        pass
    try:
        d2 = http_get_json(sess, "https://api.ipify.org?format=json", timeout=int(timeout), retries=1, proxies=p)
        ip2 = d2.get("ip")
        if ip2:
            return ip2, {}
    except Exception:
        pass
    return None, {}

def dns_leak_marker(proxy_url: Optional[str]) -> str:
    if not proxy_url:
        return "N/A"
    if proxy_url.startswith("socks5://"):
        return "LOCAL_DNS?"
    if proxy_url.startswith("socks5h://"):
        return "OK"
    return "OK"

def doh_sanity_check(session: requests.Session, proxy_url: Optional[str]) -> bool:
    try:
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        r = session.get("https://cloudflare-dns.com/dns-query?name=example.com&type=A",
                        headers={"accept": "application/dns-json"}, timeout=6, proxies=proxies)
        return r.ok
    except Exception:
        return False

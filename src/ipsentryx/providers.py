from __future__ import annotations
import requests, re
from typing import Any, Dict, Optional

DEFAULT_TIMEOUT = 12
DEFAULT_RETRIES = 2
SCAMALYTICS_RX = re.compile(r"Fraud Score:\s*([0-9]{1,3})", re.I)

def _get_json(session: requests.Session, url: str, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES, headers=None, proxies=None) -> Dict[str, Any]:
    last = None
    for attempt in range(retries + 1):
        try:
            r = session.get(url, headers=headers or {}, timeout=timeout, proxies=proxies)
            if r.status_code in (429, 502, 503, 504):
                raise requests.HTTPError(f"http {r.status_code}")
            r.raise_for_status()
            try:
                return r.json()
            except Exception:
                return {"_raw": r.text}
        except Exception as e:
            last = e
    raise last if last else RuntimeError("network error")

def ipwho(session: requests.Session, ip: str) -> Dict[str, Any]:
    data = _get_json(session, f"https://ipwho.is/{ip}")
    return {
        "ok": bool(data.get("success", False)),
        "country": data.get("country"),
        "region": data.get("region"),
        "city": data.get("city"),
        "org": (data.get("connection") or {}).get("org") or data.get("org"),
        "isp": (data.get("connection") or {}).get("isp") or data.get("isp"),
        "asn": (data.get("connection") or {}).get("asn") or data.get("asn"),
        "security": data.get("security") or {},
        "_raw": data,
    }

def ipapi(session: requests.Session, ip: str) -> Dict[str, Any]:
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query"
    data = _get_json(session, url)
    ok = data.get("status") == "success"
    return {
        "ok": ok,
        "country": data.get("country"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "org": data.get("org"),
        "isp": data.get("isp"),
        "asn": data.get("as"),
        "proxy": data.get("proxy"),
        "hosting": data.get("hosting"),
        "_raw": data,
    }

def abuseipdb(session: requests.Session, ip: str, key: Optional[str]) -> Dict[str, Any]:
    if not key:
        return {"enabled": False}
    try:
        r = session.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            headers={"Key": key, "Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT,
        )
        r.raise_for_status()
        payload = r.json().get("data", {}) if r.text else {}
        return {
            "enabled": True,
            "score": int(payload.get("abuseConfidenceScore", 0) or 0),
            "total_reports": int(payload.get("totalReports", 0) or 0),
            "is_whitelisted": bool(payload.get("isWhitelisted", False)),
            "isp": payload.get("isp"),
            "domain": payload.get("domain"),
            "_raw": payload,
        }
    except Exception as e:
        return {"enabled": True, "error": str(e)}

def ipinfo(session: requests.Session, ip: str, token: Optional[str]) -> Dict[str, Any]:
    if not token:
        return {"enabled": False}
    try:
        data = _get_json(session, f"https://ipinfo.io/{ip}?token={token}")
        privacy = data.get("privacy") or {}
        org = data.get("org") or ""
        asn = org.split()[0] if org.startswith("AS") else ""
        return {
            "enabled": True,
            "asn": asn,
            "org": org,
            "hosting": bool(privacy.get("hosting")),
            "proxy": bool(privacy.get("proxy")),
            "vpn": bool(privacy.get("vpn")),
            "tor": bool(privacy.get("tor")),
            "anycast": bool(data.get("anycast")),
            "_raw": data,
        }
    except Exception as e:
        return {"enabled": True, "error": f"ipinfo: {e}"}

def ipqs(session: requests.Session, ip: str, key: Optional[str]) -> Dict[str, Any]:
    if not key:
        return {"enabled": False}
    try:
        data = _get_json(session, f"https://ipqualityscore.com/api/json/ip/{key}/{ip}?strictness=1&allow_public_access_points=true")
        return {
            "enabled": True,
            "fraud_score": data.get("fraud_score"),
            "proxy": bool(data.get("proxy")),
            "vpn": bool(data.get("vpn")),
            "tor": bool(data.get("tor")),
            "recent_abuse": bool(data.get("recent_abuse")),
            "_raw": data,
        }
    except Exception as e:
        return {"enabled": True, "error": f"ipqs: {e}"}

def scamalytics(session: requests.Session, ip: str, enabled: bool) -> Dict[str, Any]:
    if not enabled:
        return {"enabled": False}
    try:
        r = session.get(f"https://scamalytics.com/ip/{ip}", timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return {"enabled": True, "error": f"http {r.status_code}"}
        m = SCAMALYTICS_RX.search(r.text or "")
        score = int(m.group(1)) if m else None
        return {"enabled": True, "fraud_score": score}
    except Exception as e:
        return {"enabled": True, "error": f"scamalytics: {e}"}

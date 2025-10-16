from __future__ import annotations
from typing import Any, Dict, List

HOSTING_KEYWORDS = {
    "amazon","aws","google","google llc","gcp","digitalocean","ovh","hetzner","contabo","linode",
    "scaleway","leaseweb","m247","akamai","vultr","choopa","azure","microsoft","oracle cloud",
    "equinix","ovhcloud","choopa llc","frantech","buyvm","hcloud","do-sp","lease web"
}

def _norm(s: Any) -> str:
    if s is None:
        return ""
    try:
        return str(s).replace("\n", " ").strip()
    except Exception:
        return ""

def _hosting_heuristic(org: str, asn: str) -> bool:
    low = f"{org} {asn}".lower()
    return any(k in low for k in HOSTING_KEYWORDS)

def verdict(ipwho: Dict[str, Any], ipapi: Dict[str, Any], abuse: Dict[str, Any]) -> tuple[str, List[str]]:
    reasons: List[str] = []

    sec = ipwho.get("security") or {}
    if sec.get("proxy"): reasons.append("ipwho:proxy")
    if sec.get("vpn"): reasons.append("ipwho:vpn")
    if sec.get("tor"): reasons.append("ipwho:tor")
    if sec.get("hosting"): reasons.append("ipwho:hosting")
    if ipapi.get("proxy"): reasons.append("ipapi:proxy")
    if ipapi.get("hosting"): reasons.append("ipapi:hosting")

    org = _norm(ipwho.get("org")) or _norm(ipwho.get("isp")) or _norm(ipapi.get("org")) or _norm(ipapi.get("isp"))
    asn = _norm(ipwho.get("asn")) or _norm(ipapi.get("asn"))
    if _hosting_heuristic(org, asn):
        reasons.append("hosting-asn-heuristic")

    if ipwho.get("ok") and ipapi.get("ok"):
        c1, c2 = ipwho.get("country"), ipapi.get("country")
        if c1 and c2 and c1 != c2:
            reasons.append(f"geo-mismatch:{c1}!={c2}")

    if abuse.get("enabled"):
        if "error" in abuse:
            reasons.append("abuseipdb:error")
        else:
            score = int(abuse.get("score", 0))
            reports = int(abuse.get("total_reports", 0))
            if score >= 25 and reports >= 3:
                reasons.append(f"abuseipdb:{score}/{reports}")

    return ("SUSPICIOUS", reasons) if reasons else ("CLEAN", ["no-flags"])

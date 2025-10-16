from __future__ import annotations
import argparse, csv, json, logging, os, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests

from ipsentryx.utils import bounded_expand, jitter_sleep
from ipsentryx import providers as p
from ipsentryx import verdicts
from ipsentryx import proxy as prx
from ipsentryx import dnsbl

log = logging.getLogger("ipsentryx")

def _mk_adapter(threads: int) -> requests.adapters.HTTPAdapter:
    return requests.adapters.HTTPAdapter(pool_connections=threads, pool_maxsize=threads, max_retries=0)

def _mk_sessions(threads: int) -> Tuple[requests.Session, requests.Session, requests.Session, requests.Session]:
    s1 = requests.Session(); s2 = requests.Session(); s3 = requests.Session(); s4 = requests.Session()
    ad = _mk_adapter(threads)
    for s in (s1, s2, s3, s4):
        s.mount("http://", ad); s.mount("https://", ad)
    return s1, s2, s3, s4

def _row_from_results(ip: str, ipwho: Dict[str, Any], ipapi: Dict[str, Any], abuse: Dict[str, Any],
                      ipinfo: Dict[str, Any], ipqs: Dict[str, Any], scam: Dict[str, Any], spam: Dict[str, Any],
                      verdict: str, reasons: List[str], short_flags: List[str]) -> Dict[str, Any]:
    country = (ipwho.get("country") or ipapi.get("country") or "") or ""
    region  = (ipwho.get("region") or ipapi.get("region") or "") or ""
    city    = (ipwho.get("city") or ipapi.get("city") or "") or ""
    org     = (ipwho.get("org") or ipapi.get("org") or "") or ""
    isp     = (ipwho.get("isp") or ipapi.get("isp") or "") or ""
    asn     = (ipwho.get("asn") or ipapi.get("asn") or "") or ""
    sec = ipwho.get("security") or {}
    row: Dict[str, Any] = {
        "IP": ip,
        "Country": country, "Region": region, "City": city, "ORG": org, "ISP": isp, "ASN": asn,
        "ipwho_proxy": int(bool(sec.get("proxy"))) if sec else 0,
        "ipwho_vpn": int(bool(sec.get("vpn"))) if sec else 0,
        "ipwho_tor": int(bool(sec.get("tor"))) if sec else 0,
        "ipwho_hosting": int(bool(sec.get("hosting"))) if sec else 0,
        "ipapi_proxy": int(bool(ipapi.get("proxy"))),
        "ipapi_hosting": int(bool(ipapi.get("hosting"))),
        "Abuse_Score": abuse.get("score") if abuse.get("enabled") and "error" not in abuse else "",
        "Abuse_Reports": abuse.get("total_reports") if abuse.get("enabled") and "error" not in abuse else "",
        "IPQS_FraudScore": ipqs.get("fraud_score") if ipqs.get("enabled") and "error" not in ipqs else "",
        "IPQS_Proxy": int(bool(ipqs.get("proxy"))) if ipqs.get("enabled") and "error" not in ipqs else "",
        "IPQS_VPN": int(bool(ipqs.get("vpn"))) if ipqs.get("enabled") and "error" not in ipqs else "",
        "IPQS_Tor": int(bool(ipqs.get("tor"))) if ipqs.get("enabled") and "error" not in ipqs else "",
        "IPQS_RecentAbuse": int(bool(ipqs.get("recent_abuse"))) if ipqs.get("enabled") and "error" not in ipqs else "",
        "IPINFO_PrivacyProxy": int(bool(ipinfo.get("proxy"))) if ipinfo.get("enabled") and "error" not in ipinfo else "",
        "IPINFO_PrivacyVpn": int(bool(ipinfo.get("vpn"))) if ipinfo.get("enabled") and "error" not in ipinfo else "",
        "IPINFO_Hosting": int(bool(ipinfo.get("hosting"))) if ipinfo.get("enabled") and "error" not in ipinfo else "",
        "IPINFO_Anycast": int(bool(ipinfo.get("anycast"))) if ipinfo.get("enabled") and "error" not in ipinfo else "",
        "IPINFO_ASN": ipinfo.get("asn") if ipinfo.get("enabled") and "error" not in ipinfo else "",
        "SpamhausListed": (1 if spam.get("enabled") and spam.get("listed") else 0) if spam.get("enabled") else "",
        "SpamhausZones": "|".join(spam.get("codes", [])) if spam.get("enabled") else "",
        "Scamalytics_FraudScore": scam.get("fraud_score") if scam.get("enabled") and "error" not in scam else "",
        "Verdict": verdict,
        "Flags": "; ".join(reasons) if reasons else "-",
        "FlagsShort": ", ".join(short_flags) if short_flags else "-",
        "Proxy": "", "DNSLeak": "",
    }
    for prov in (ipinfo, ipqs, scam):
        if prov.get("enabled") and prov.get("error"):
            row["Flags"] = (row["Flags"] + f"; {prov['error']}").strip("; ")
    if spam.get("enabled") and spam.get("listed"):
        row["Flags"] = (row["Flags"] + "; spamhaus:listed").strip("; ")
    return row

def _short_flags(ipwho: Dict[str, Any], ipapi: Dict[str, Any], ipinfo: Dict[str, Any], ipqs: Dict[str, Any]) -> List[str]:
    sec = ipwho.get("security") or {}
    out: List[str] = []
    if sec.get("proxy"): out.append("ipwho:proxy")
    if sec.get("vpn"): out.append("ipwho:vpn")
    if sec.get("tor"): out.append("ipwho:tor")
    if sec.get("hosting"): out.append("ipwho:hosting")
    if ipapi.get("proxy"): out.append("ipapi:proxy")
    if ipapi.get("hosting"): out.append("ipapi:hosting")
    if ipinfo.get("enabled") and "error" not in ipinfo:
        if ipinfo.get("proxy"): out.append("ipinfo:proxy")
        if ipinfo.get("vpn"): out.append("ipinfo:vpn")
        if ipinfo.get("tor"): out.append("ipinfo:tor")
        if ipinfo.get("hosting"): out.append("ipinfo:hosting")
    if ipqs.get("enabled") and "error" not in ipqs:
        fs = ipqs.get("fraud_score")
        if isinstance(fs, int): out.append(f"ipqs:{fs}")
    return out

def _write_csv(rows: List[Dict[str, Any]], path: str) -> None:
    cols = [
        "IP","Country","Region","City","ORG","ISP","ASN",
        "ipwho_proxy","ipwho_vpn","ipwho_tor","ipwho_hosting",
        "ipapi_proxy","ipapi_hosting",
        "Abuse_Score","Abuse_Reports",
        "IPQS_FraudScore","IPQS_Proxy","IPQS_VPN","IPQS_Tor","IPQS_RecentAbuse",
        "IPINFO_PrivacyProxy","IPINFO_PrivacyVpn","IPINFO_Hosting","IPINFO_Anycast","IPINFO_ASN",
        "SpamhausListed","SpamhausZones",
        "Scamalytics_FraudScore",
        "Verdict","Flags","FlagsShort",
        "Proxy","DNSLeak"
    ]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})

def _write_jsonl(rows: List[Dict[str, Any]], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def _process_ip(ip: str, sessions, abuse_key: Optional[str], sleep_min: float, sleep_max: float,
                ipinfo_token: Optional[str], ipqs_key: Optional[str],
                scamalytics_en: bool, spamhaus_en: bool, spam_resolver: str) -> Dict[str, Any]:
    s_ipwho, s_ipapi, s_abuse, s_ext = sessions
    jitter_sleep(sleep_min, sleep_max)
    ipwho = p.ipwho(s_ipwho, ip)
    jitter_sleep(sleep_min, sleep_max)
    ipapi = p.ipapi(s_ipapi, ip)
    abuse = p.abuseipdb(s_abuse, ip, abuse_key)
    ipinfo = p.ipinfo(s_ext, ip, ipinfo_token)
    ipqs = p.ipqs(s_ext, ip, ipqs_key)
    scam = p.scamalytics(s_ext, ip, scamalytics_en)
    spam = dnsbl.spamhaus_lookup(ip, spam_resolver) if spamhaus_en else {"enabled": False}
    v, reasons = verdicts.verdict(ipwho, ipapi, abuse)
    sf = _short_flags(ipwho, ipapi, ipinfo, ipqs)
    return _row_from_results(ip, ipwho, ipapi, abuse, ipinfo, ipqs, scam, spam, v, reasons, sf)

def _process_proxy(line: str, args, sessions, abuse_key: Optional[str]) -> Dict[str, Any]:
    proxy_url = prx.parse_proxy_line(line, default_scheme=args.proxy_scheme)
    if not proxy_url:
        return {"IP":"", "Verdict":"ERROR", "Flags":"bad-proxy-line", "FlagsShort":"-", "Proxy": line.strip(), "DNSLeak":""}
    ip, _meta = prx.resolve_exit_ip(proxy_url, timeout=args.proxy_timeout)
    if not ip:
        return {"IP":"", "Verdict":"ERROR", "Flags":"cannot-resolve-exit-ip", "FlagsShort":"-", "Proxy": proxy_url, "DNSLeak":""}
    row = _process_ip(
        ip, sessions, abuse_key, args.sleep_min, args.sleep_max,
        args.ipinfo_token, args.ipqs_key, args.scamalytics, args.spamhaus, args.dns_resolver
    )
    row["Proxy"] = proxy_url
    if args.dns_leak_check:
        marker = prx.dns_leak_marker(proxy_url)
        doh_ok = prx.doh_sanity_check(sessions[0], proxy_url)
        row["DNSLeak"] = "OK" if (marker == "OK" and doh_ok) else marker
    return row

def _add_common_scan_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--threads", type=int, help="Количество потоков (по умолчанию CPU*5)")
    sp.add_argument("--sleep-min", type=float, default=0.15)
    sp.add_argument("--sleep-max", type=float, default=0.35)
    sp.add_argument("--out", default="out/report.csv")
    sp.add_argument("--out-format", choices=["csv","jsonl"], default="csv")
    sp.add_argument("--ipinfo-token")
    sp.add_argument("--ipqs-key")
    sp.add_argument("--scamalytics", action="store_true")
    sp.add_argument("--spamhaus", action="store_true")
    sp.add_argument("--dns-resolver", default="8.8.8.8")
    sp.add_argument("--no-abuse", action="store_true")

def _save(rows: List[Dict[str, Any]], path: str, fmt: str) -> None:
    if fmt == "csv":
        _write_csv(rows, path)
    else:
        _write_jsonl(rows, path)

def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(prog="ip-sentryx", description="Mass IP/Proxy reputation scanner")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sp_ips = sub.add_parser("scan ips", help="Проверить IP или CIDR")
    sp_ips.add_argument("--input", help="Файл со списком IP/CIDR (один на строку)")
    sp_ips.add_argument("--max-expand", type=int, default=100000)
    sp_ips.add_argument("targets", nargs="*", help="IP или CIDR")
    _add_common_scan_args(sp_ips)

    sp_px = sub.add_parser("scan proxies", help="Проверить список прокси")
    sp_px.add_argument("--proxies", required=True, help="Файл прокси: host:port[:user:pass] или URL (http/socks5/socks5h)")
    sp_px.add_argument("--proxy-scheme", default="http")
    sp_px.add_argument("--proxy-timeout", type=float, default=8.0)
    sp_px.add_argument("--dns-leak-check", action="store_true")
    _add_common_scan_args(sp_px)

    args = parser.parse_args()

    cpu = os.cpu_count() or 4
    threads = args.threads if (getattr(args, "threads", None) or 0) > 0 else cpu * 5
    sessions = _mk_sessions(threads)
    abuse_key = None if getattr(args, "no-abuse", False) else os.environ.get("ABUSEIPDB_KEY")

    if args.cmd == "scan proxies":
        if not os.path.exists(args.proxies):
            print(f"Файл не найден: {args.proxies}")
            return 2
        lines = [ln.strip() for ln in open(args.proxies, "r", encoding="utf-8") if ln.strip()]
        total = len(lines)
        rows: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = [ex.submit(_process_proxy, ln, args, sessions, abuse_key) for ln in lines]
            done = 0
            for fut in as_completed(futs):
                try:
                    rows.append(fut.result())
                except Exception as e:
                    rows.append({"IP":"", "Verdict":"ERROR", "Flags":str(e), "FlagsShort":"-", "Proxy":"", "DNSLeak":""})
                done += 1
                if done % max(1, total // 20) == 0 or done == total:
                    print(f"Готово {done}/{total} ({done*100//total}%)")
        _save(rows, args.out, args.out_format)
        print(f"Результат сохранён: {args.out}")
        return 0

    # scan ips
    raw: List[str] = []
    if args.input and os.path.exists(args.input):
        raw.extend([ln.strip() for ln in open(args.input, "r", encoding="utf-8") if ln.strip()])
    if args.targets:
        raw.extend([t.strip() for t in args.targets if t.strip()])

    if not raw:
        print("Не переданы цели. Используйте --input или позиционные аргументы.")
        return 2

    targets = bounded_expand(raw, args.max_expand)
    total = len(targets)
    rows: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(
            _process_ip, ip, sessions, abuse_key,
            args.sleep_min, args.sleep_max,
            args.ipinfo_token, args.ipqs_key,
            args.scalamalytics if hasattr(args, "scalamalytics") else args.scamalytics,
            args.spamhaus, args.dns_resolver
        ) for ip in targets]
        done = 0
        for fut in as_completed(futs):
            try:
                rows.append(fut.result())
            except Exception as e:
                rows.append({"IP":"", "Verdict":"ERROR", "Flags":str(e), "FlagsShort":"-"})
            done += 1
            if done % max(1, total // 20) == 0 or done == total:
                print(f"Готово {done}/{total} ({done*100//total}%)")

    _save(rows, args.out, args.out_format)
    print(f"Результат сохранён: {args.out}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

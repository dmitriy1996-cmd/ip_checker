from __future__ import annotations
from typing import Dict, Any

def spamhaus_lookup(ip: str, resolver_ip: str = "8.8.8.8") -> Dict[str, Any]:
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return {"enabled": True, "listed": False, "error": "dnspython not installed"}
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        qname = f"{reversed_ip}.zen.spamhaus.org"
        res = dns.resolver.Resolver(configure=True)
        res.nameservers = [resolver_ip]
        answers = res.resolve(qname, "A")
        listed = [str(r) for r in answers]
        txt = []
        try:
            for rr in res.resolve(qname, "TXT"):
                try:
                    parts = getattr(rr, "strings", None)
                    if parts:
                        txt.append(b"".join(parts).decode("utf-8", "ignore"))
                    else:
                        txt.append(rr.to_text().strip('"'))
                except Exception:
                    pass
        except Exception:
            pass
        return {"enabled": True, "listed": True, "codes": listed, "txt": "|".join(txt)}
    except Exception:
        return {"enabled": True, "listed": False}

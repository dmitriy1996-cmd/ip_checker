from __future__ import annotations
import ipaddress, random, time, logging
from typing import Iterable, Iterator, List

log = logging.getLogger("ipsentryx")

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def expand_target(token: str) -> Iterator[str]:
    t = token.strip()
    if not t:
        return iter(())
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
            # Для маленьких сетей возвращаем все адреса, иначе .hosts()
            return (str(ip) for ip in net.hosts()) if net.num_addresses > 2 else (str(ip) for ip in net)
        except ValueError:
            return iter(())
    return iter((t,)) if is_ip(t) else iter(())

def bounded_expand(tokens: Iterable[str], limit: int) -> List[str]:
    out: List[str] = []
    for tok in tokens:
        for ip in expand_target(tok):
            out.append(ip)
            if len(out) >= limit:
                return out
    return out

def jitter_sleep(a: float, b: float) -> None:
    time.sleep(random.uniform(a, b))

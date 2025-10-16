from ipsentryx.utils import is_ip, bounded_expand

def test_is_ip():
    assert is_ip("8.8.8.8")
    assert not is_ip("nope")

def test_bounded_expand_small_cidr():
    out = bounded_expand(["203.0.113.0/30"], 10)
    assert len(out) >= 2  # для крохотных сетей возвращаем все адреса

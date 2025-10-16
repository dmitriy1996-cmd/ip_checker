# ip-sentryx

Модульный сканер репутации IP-адресов и прокси с поддержкой сторонних провайдеров (ipwho.is, ip-api, AbuseIPDB, IPinfo, IPQualityScore, Scamalytics) и DNSBL Spamhaus, а также маркерами DNS-утечек для SOCKS5/SOCKS5H. Подходит для антифрода, OSINT, арбитражных проверок и сетевой гигиены.

## Особенности

- Модульная архитектура: провайдеры, прокси-утилиты, DNSBL, вердикты разделены по файлам.
- Два режима:  
  • `scan ips` — массовая проверка IP/CIDR  
  • `scan proxies` — резолв exit-IP каждого прокси и проверка как обычного IP  
- Плагинные источники (включаются флагами CLI): ipwho.is, ip-api, AbuseIPDB, IPinfo, IPQualityScore, Scamalytics, Spamhaus.
- Вывод в CSV или JSONL на выбор (`--out-format csv|jsonl`).
- Маркеры DNS-утечек: различение `socks5` (локальный DNS) vs `socks5h` (удалённый DNS) и DoH-проверка.
- Умный параллелизм, пулы соединений `requests`, бэкофф при ошибках.
- Готовая проектная обвязка: `pyproject.toml`, `ruff/mypy`, `pre-commit`, GitHub Actions, примеры и тесты.

## Установка

**Требования**: Python 3.9+

```bash
# В корне проекта
pip install -e .
```
## Опционально (для Spamhaus DNSBL и дев-инструментов):

```bash
pip install -e .[dns,dev]
```

Появится консольная команда:

```bash
ip-sentryx --help
```

## Быстрый старт
### Проверка IP / CIDR

```bash
# Linux / macOS
ip-sentryx scan ips --input examples/ips.txt --out out/report.csv
# или JSONL
ip-sentryx scan ips --input examples/ips.txt --out out/report.jsonl --out-format jsonl
```

```powershell
# Windows PowerShell
ip-sentryx scan ips --input .\examples\ips.txt --out .\out\report.csv
```

### Проверка прокси

```bash
ip-sentryx scan proxies --proxies examples/proxies.txt --out out/proxies.csv --dns-leak-check
```

Строки прокси поддерживаются в форматах:

- host:port
- host:port:user:pass
- http[s]://user:pass@host:port
- socks5://user:pass@host:port
- socks5h://user:pass@host:port

Для «коротких» строк можно задать схему по умолчанию:

```bash
ip-sentryx scan proxies --proxies examples/proxies.txt --proxy-scheme socks5h
```

### Подключение провайдеров

Некоторые источники требуют ключ/токен. Включайте их флагами CLI и/или переменными окружения:

- AbuseIPDB: переменная окружения ABUSEIPDB_KEY
Пример:

```bash
ABUSEIPDB_KEY="your_key" ip-sentryx scan ips --input examples/ips.txt
```
Отключить даже при наличии ключа:
```bash
ip-sentryx scan ips --input examples/ips.txt --no-abuse
```

- IPinfo: флаг --ipinfo-token YOUR_TOKEN
- IPQualityScore: флаг --ipqs-key YOUR_KEY
- Scamalytics (щадящий скрейп публичной страницы): --scamalytics
- Spamhaus ZEN (DNSBL): --spamhaus и при необходимости --dns-resolver 1.1.1.1

Комбинированный пример:

```bash
ABUSEIPDB_KEY="..." \
ip-sentryx scan ips --input examples/ips.txt \
  --ipinfo-token "..." --ipqs-key "..." \
  --spamhaus --dns-resolver 1.1.1.1 \
  --scamalytics \
  --out out/full.csv
```

### Параметры CLI (общее)

- threads — число потоков (по умолчанию ≈ CPU * 5).
- sleep-min / --sleep-max — джиттерные паузы между запросами на поток (смягчают rate-limit).
- out — путь для вывода (out/report.csv по умолчанию).
- out-format csv|jsonl — формат результата (CSV по умолчанию).

Провайдеры: --ipinfo-token, --ipqs-key, --scamalytics, --spamhaus, --dns-resolver, --no-abuse.

Подкоманда scan ips

Источники целей: позиционные аргументы (IP/CIDR) и/или --input path.

--max-expand — лимит развёртывания CIDR (по умолчанию 100000).

Примеры:

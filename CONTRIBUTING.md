# Contributing

1. Создайте ветку feature/...
2. Запускайте линтеры и тесты:
   ```bash
   pip install -e .[dev,dns]
   ruff check .
   mypy src
   pytest -q

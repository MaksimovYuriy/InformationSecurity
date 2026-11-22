# Cloud Storage Audit

Локальное приложение проверки безопасности VK Cloud Object Storage (S3). Собирает настройки выбранного бакета, выполняет восемь правил, оценивает риск, выдаёт рекомендации и сохраняет отчёты. Поддерживает ограниченные анонимные пробы, историю, сравнение запусков и JSON/Markdown-экспорт. Добавлен ступенчатый scan нескольких бакетов: внешний этап без подписи и внутренний при наличии ключей. ИИ-помощник запланирован на итерацию 12 и пока не реализован.

## Быстрый запуск

Python 3.12 или новее, из корня репозитория:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
PYTHONPATH=src .venv/bin/python -m cloud_audit check
PYTHONPATH=src .venv/bin/python -m cloud_audit --help
```

Для живого S3 нужны переменные окружения из `.env.example`. Имя бакета передаётся через `--resource`; настройки подключения общие для нескольких бакетов. Приложение не загружает `.env` автоматически. Порядок безопасной настройки — в [руководстве](docs/USER_GUIDE.md).

```bash
PYTHONPATH=src .venv/bin/python -m cloud_audit scan --targets scan-targets.example.json
PYTHONPATH=src .venv/bin/python -m cloud_audit scan --all-buckets
PYTHONPATH=src .venv/bin/python -m cloud_audit resources --profile vk
PYTHONPATH=src .venv/bin/python -m cloud_audit audit --profile vk --resource BUCKET_NAME --objects synthetic.txt --probe-anonymous
PYTHONPATH=src .venv/bin/python -m cloud_audit report REPORT_ID --format markdown --output report.md
PYTHONPATH=src .venv/bin/python -m cloud_audit history --resource BUCKET_NAME
PYTHONPATH=src .venv/bin/python -m cloud_audit compare BEFORE_ID AFTER_ID
```

Выбирайте искусственные файлы. Без двух явных флагов мутационные пробы выключены. Обычный аудитор настройки бакета не исправляет. Повторный анализ через `audit --profile vk --snapshot SNAPSHOT_ID` не обращается к облаку и не является новой проверкой исправления.

Для знакомства без ключей:

```bash
PYTHONPATH=src .venv/bin/python -m cloud_audit audit --profile demo --resource demo-public
```

Demo выдаёт simulated, не реальную оценку безопасности.

## Структура одного приложения

```text
src/cloud_audit/
  cli.py, __main__.py   команды и запуск
  models/              данные: ресурсы, снимки, находки, отчёты
  rules/               алгоритмы восьми проверок, движок и риск
  services/            сценарии сбора, аудита, истории и сравнения
  providers/           S3, нормализация, unsigned-пробы, demo
  storage/             SQLite, JSON, схемы и состояние
  configuration/       настройки окружения и политика аудита
  reports/             фильтры представления, Markdown и экспорт
  interfaces.py        контракты внедряемых зависимостей
  errors.py            контролируемые ошибки
```

Один Python-пакет, без обязательного сервера или HTTP API. Слои зависимости отделены по назначению, чтобы правила и сценарии не зависели от boto3/SQLite. История хранится в `.state/data/audit.sqlite3`; снимки — в `.state/data/snapshots`. Прежние JSON доступны для чтения и явного импорта.

## Документация

Начать с [карты документации](docs/README.md).

- [Спецификация и текущее состояние](docs/PROJECT_SPECIFICATION.md)
- [Архитектура: что, как и почему](docs/ARCHITECTURE.md)
- [Полный справочник исходного кода](docs/CODE_REFERENCE.md)
- [Модели, конфигурация и форматы хранения](docs/DATA_CONTRACTS.md)
- [Ступенчатая проверка нескольких бакетов](docs/STAGED_SCAN.md)
- [Все правила и порядок сканирования](docs/SCANNING.md)
- [Обоснование выбора правил](docs/rules/RULE_CATALOG.md)
- [Установка, команды и демонстрация](docs/USER_GUIDE.md)
- [Тестирование и перечень сценариев](docs/TESTING.md)
- [Матрица соответствия исходному заданию](docs/ACCEPTANCE_MATRIX.md)
- [План разработки](DEVELOPMENT_ITERATIONS.md), [правила разработки](AGENTS.md)

## Проверка

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/build_code_reference.py --check
```

Для новых ступенчатых проверок: `-p 'test_staged_*.py'`. Для приёмочных CLI-сценариев отдельно: `-p 'test_acceptance.py'`. Тесты автоматически не обращаются к реальному облаку. Для явно включаемого временного стенда используется `scripts/verify_public_access.py --run-training-fixture`; условия и уборка описаны в руководстве.

Успех команды (код 0) не означает отсутствие находок. Код 3 обозначает частичность/недостаток данных либо неподтверждённое сравнение. Condition/Not*, полный IAM, все объекты/версии и фактический вход внешних субъектов не анализируются полностью; ограничения сохраняются в отчёте.

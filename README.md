# Cloud Storage Audit

Локальное приложение проверки безопасности VK Cloud Object Storage (S3). Собирает настройки выбранного бакета, выполняет восемь правил, оценивает риск, выдаёт рекомендации и сохраняет отчёты. Поддерживает ограниченные анонимные пробы, историю, сравнение запусков и JSON/Markdown-экспорт. Добавлен ступенчатый scan нескольких бакетов: внешний этап без подписи и внутренний при наличии ключей. ИИ-помощник запланирован на итерацию 12 и пока не реализован.

## Быстрый запуск

В подготовленном проекте достаточно одной команды; замени имя учебного бакета:

```bash
./cloud-audit scan --buckets my-training-bucket
```

`.env` из текущего каталога загружается автоматически как данные, без shell. Пара ключей включает внутренний этап; без ключей выполняется внешний. Мутационные пробы по умолчанию выключены. [Краткая инструкция](docs/MANUAL_TEST.md).

Первая установка на новом компьютере (Python 3.12+):

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -e .
```

`./cloud-audit` использует локальную `.venv`, активация и PYTHONPATH не нужны. После активации `.venv` также доступна установленная команда `cloud-audit`. Процессное окружение имеет приоритет над `.env`; общие `--env-file PATH` и `--no-env-file` ставятся перед подкомандой.

```bash
./cloud-audit scan --buckets bucket-one bucket-two
./cloud-audit scan --all-buckets
./cloud-audit scan --targets scan-targets.example.json
./cloud-audit scan-report SCAN_ID --format markdown --output report.md
./cloud-audit audit --profile demo --resource demo-public
```

Demo выдаёт simulated. Обычный аудитор настройки не исправляет. Офлайн-аудит сохранённого снимка не является новой проверкой исправления. Отдельный сервер не нужен.

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
- [Пошаговая самостоятельная проверка](docs/MANUAL_TEST.md)
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

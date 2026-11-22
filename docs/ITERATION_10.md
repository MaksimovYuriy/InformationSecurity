# Итерация 10: рефакторинг и документация основной части

## Статус

Завершена. Выполнены очистка временного кода, предметная структура одного приложения, логические имена тестов, полный регрессионный прогон и документация всех модулей/определений. ИИ-помощник остаётся отдельной итерацией 11.

CLI, версии отчётов/снимков, пути состояния и SQLite-схема сохранены. Внутренние import-пути изменены без совместимых реэкспортных заглушек; сохранённые данные миграции не требуют.

## Что удалено или упрощено

- Удалён одноразовый `scripts/run_iteration09.py`; приёмка теперь обычный `test_acceptance.py`, весь набор запускается unittest discovery.
- У S3Provider удалены preview с сообщением «не реализовано» и неактуальный audit_available. У DemoProvider также убран ненужный флаг.
- Демонстрационный сценарий называется ProfileService.simulate и отклоняет облачный профиль. Реальный SecurityAuditService.audit сохраняется отдельно; это не замена настоящего аудита имитацией.
- Общие ошибки вынесены в errors.py, Protocol-контракты — в interfaces.py; провайдеры/хранилища больше не импортируют сервис ради исключения.
- RiskModel отделён от моделей данных, S3Settings перенесён к настройкам-моделям.
- Убраны неиспользуемые импорты. Общие построители тестовых данных вынесены в audit_fixtures.py: тестовые модули больше не импортируют друг друга.
- Старые каталоги domain/application/infrastructure удалены, а не оставлены пустыми/с заглушками. Данные `.state` и `.env` не очищались.

Demo и JsonReportRepository сохранены намеренно: первый — поддерживаемый запуск без облака, второй — совместимость/импорт прежних данных и тестовые репозитории. Это используемые возможности, не временные остатки.

## Соответствие модулей

Пути относительно `src/cloud_audit/`:

| Было | Стало |
|---|---|
| application/audit.py | services/profiles.py; AuditService → ProfileService, audit → simulate |
| application/security_audit.py | services/audit.py |
| application/snapshot.py | services/snapshots.py |
| application/environment.py | services/environment.py |
| application/history.py | services/history.py |
| application/comparison.py | services/comparison.py |
| application/rules.py | rules/engine.py |
| application/rule_registry.py | rules/registry.py |
| domain/audit.py | models/resources.py |
| domain/rules.py | models/security.py; RiskModel → rules/risk.py; SecurityRule → interfaces.py |
| domain/snapshot.py | models/snapshot.py |
| domain/settings.py | models/settings.py, также S3Settings |
| domain/history.py | models/history.py |
| domain/versioning.py | rules/versioning.py |
| domain/public_access.py | rules/public_access.py |
| domain/access_grants.py | rules/access_grants.py |
| domain/governance_rules.py | rules/governance.py |
| infrastructure/configuration.py | configuration/environment.py; ConfigurationError → errors.py |
| infrastructure/audit_policy.py | configuration/policy.py |
| infrastructure/s3.py | providers/s3.py |
| infrastructure/s3_configuration.py | providers/collection.py |
| infrastructure/anonymous.py | providers/anonymous.py |
| infrastructure/demo.py | providers/demo.py |
| infrastructure/storage.py | storage/state.py |
| infrastructure/reports.py | storage/json_reports.py |
| infrastructure/snapshots.py | storage/snapshots.py |
| infrastructure/history.py | storage/sqlite.py |
| infrastructure/security_report_schema.py | storage/report_schema.py |
| infrastructure/snapshot_schema.py | storage/snapshot_schema.py |
| infrastructure/formatting.py | reports/formatting.py |

`AuditError` перенесён из старого application/audit.py в errors.py. Protocol-контракты выделены из старых сервисов в interfaces.py, включая отдельный SimulationProvider. Остальные внутренние классы сохраняют свои предметные имена.

## Соответствие тестов

| Было | Стало |
|---|---|
| test_iteration07_rules.py | test_governance_rules.py |
| test_iteration07_workflow.py | test_governance_workflow.py |
| test_iteration08_storage.py | test_audit_history.py |
| test_iteration08_comparison.py | test_report_comparison.py |
| test_iteration08_formatting.py | test_report_formatting.py |
| test_iteration08_cli.py | test_history_cli.py |
| test_iteration09_acceptance.py | test_acceptance.py |
| test_review_regressions.py | test_evidence_integrity.py |

Номера также убраны из классов. NEW_RULES → GOVERNANCE_RULES, названия методов про «новые правила» заменены предметными. Новые файлы: test_package_structure.py (четыре проверки), test_fixture_verification.py (три сценария). Все 127 исходных методов сохранены; итог — 134. Совместные данные описаны в [TESTING.md](TESTING.md), там же перечислены все файлы, классы и сценарии.

## Документация

В [карте документации](README.md) доступны:

- ARCHITECTURE: единое приложение, причины разделения, зависимости, поток запроса, контракты и расширение;
- DATA_CONTRACTS: смысл всех групп моделей, типы/схемы, настройки, SQLite, JSON, TTL, права и совместимость;
- SCANNING: весь процесс, алгоритм каждого из восьми правил, политика/ACL, пробы, риск, исключения и подтверждение исправления;
- USER_GUIDE: установка, все команды/флаги, пример использования, демонстрация, коды ошибок и состояние;
- TESTING: полный перечень проверок и воспроизведение;
- CODE_REFERENCE: каждый модуль приложения и поддерживаемый скрипт, классы, функции/методы (включая закрытые и именованные локальные), поля и константы.

В исходниках документировано каждое явно объявленное определение. Справочник автоматически строится AST-скриптом `scripts/build_code_reference.py`; `--check` подтверждает актуальность. Это поддерживаемый инструмент документации, а не одноразовый runner. Исторические протоколы сохранены и явно помечены архивными, текущие команды вынесены в руководство.

## TDD и полный прогон

1. До переноса — **127 тестов, 8,993 с, OK**.
2. Добавлены падающие структурные проверки: ожидаемые новые каталоги, запрет старых, направление зависимостей и отсутствие номеров в именах тестов.
3. После переноса/централизации — полный набор прошёл. Дополнительная падающая проверка выявила недокументированные Protocol-определения; описания дополнены.
4. Интеграционная проверка выявила хрупкость стенда при немедленной проверке изменённой политики. Три новых теста сначала падали на первом несовпадении, затем прошли с ограниченным ожиданием.
5. Финальный рабочий полный прогон — **134 теста, 8,555 с, OK**.
6. В отдельном чистом окружении Python 3.12.8 с зависимостями из requirements.txt — **134 теста, около 8,662 с вместе с запуском процесса, OK**.

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/build_code_reference.py --check
```

Проверен документированный запуск из исходников, не установка консольной точки входа пакета через pyproject.toml. Unit/CLI-тесты используют искусственные данные/SDK Stubber, не живую сеть.

## Стендовые повторы после смены политики

В первых двух реальных запусках сразу после установки политики одна из unsigned-операций ещё получала denied, другая — allowed. Аудитор корректно сохранял различие confirmed_violation/potential_risk, не выдавал желаемое за фактическое; оба стенда удалены, cleanup_ok=true. Причина различий отдельно на стороне провайдера не диагностировалась.

Стендовый скрипт теперь делает до пяти свежих проверок каждой стадии с паузами секунду, сохраняя **каждую** попытку. stage_count — число разных стадий, attempt_count — число наблюдений. Исчерпание лимита означает неуспех, finally всё равно выполняет уборку. Условия успеха не смягчены: для публичной стадии нужны оба положительных unsigned read/list, для закрытой — оба отрицательных и passed всех четырёх анонимных правил. Алгоритмы правил и их версия не менялись.

Новые тесты проверяют частичное открытие, задержку закрытия и окончательный неуспех с уборкой. Ожидание не добавлено в обычный аудитор, он продолжает показывать фактическое состояние каждого запуска.

Неуспешные попытки: `.state/data/fixture-8f10557d9a9e46519cb11e79a561f6b5.json`, `.state/data/fixture-9141a4d7a06545f9a6daead6f2389ac0.json`; они не считаются доказательством завершённого цикла.

## Успешная реальная интеграция

22.11.2026, новый бакет `cloud-audit-lab-330dd5d704474964b3fbd82d21945671`, только искусственный файл:

| Стадия | Report ID | read/list |
|---|---|---|
| closed_before | bb3917cabbce48db93aea747367e1629 | denied, passed |
| public_read_list | 8ecd2861cff34456b857316a56725abe | allowed, confirmed_violation |
| closed_after | 8c871c5fe29b4ba3863e3aa23bade99f | denied, passed |

Успешный цикл занял **5,196 с**, stage_count=3, attempt_count=3, success=true, cleanup_ok=true. Временные бакет и файл удалены; пользовательский бакет не изменялся. Положительные write/delete не выполнялись. Артефакт: `.state/data/fixture-0c82ad24d90f4259b5c66a30f57b816b.json`.

После этого в чистом окружении **без ключей**:

- сравнение closed→public: new для read/list;
- public→closed: resolved для read/list с новыми denied по тем же целям;
- чтение существовавшего до рефакторинга отчёта `0a604629dfb240bab78ffb1e44a668db` из сохранённого состояния;
- повторный аудит всех восьми правил по свежему снимку, новый отчёт `5dda76a08c70469db63deda91d277b68`;
- Markdown-экспорт `.state/data/iteration10-comparison-17246cd0e20f48c1a5a315e0712fd527.md`, права 0600.

Повторный полный аудит сохранил отдельные риски выключенного версионирования/ACL и insufficient_data для excess без baseline; код 3 ожидаем. Исправление read/list не выдаётся за безопасность всего бакета.

Приватная сводка сравнений, чтения, экспорта и полного прогона: `.state/data/iteration10-validation-7ca8597977674ffebc7aad3ed7f875eb.json`. Артефакты `.state` не входят в Git, ключи в них не включены.

## Ограничения и следующий этап

Не добавлены полный IAM/Condition/Not*, автоматическое перечисление всех объектов/версий или реальное подтверждение доступа внешних субъектов. Статистическая точность на произвольных политиках не измерялась. Минимальность прав аудитора остаётся ранее согласованным ограничением.

Основная часть оформлена и проверена. Следующая — итерация 11, ИИ-помощник. Выбор модели/Cloud.ru, MCP, Docker и возможного веб-интерфейса ещё не принят. Пояснительная записка по конкретному шаблону кафедры потребует предоставления этого шаблона; техническая документация основной части доступна сейчас.

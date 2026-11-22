# Модели, конфигурация и хранение

Типы и значения по умолчанию **каждого поля** перечислены в [CODE_REFERENCE.md](CODE_REFERENCE.md) в разделах `models/` и `services/environment.py`. Здесь описаны смысл полей, связи и инварианты. Все модели — frozen dataclass; вложенные словари не являются глубоко неизменяемыми. JSON использует массивы вместо tuple, ISO 8601 со смещением для времени и null вместо None.

## Ресурсы и демонстрация

`Resource.id` — имя бакета для S3; `name` — отображаемое имя. Идентичность настоящего результата определяется также mode и resource_namespace, поскольку одинаковое имя не должно смешивать разные endpoint.

`RuleResult` — ID демонстрационного сценария, simulated и explanation. `AuditReport` содержит UUID hex, mode=demo, Resource и такие результаты. В нём нет настоящих доказательств, времени сбора и риска; сравнение настоящих отчётов его отклоняет.

## Настройки

`Settings`: environment — development/test/production; log_level — DEBUG/INFO/WARNING/ERROR/CRITICAL; state_dir — выделенный Path локального состояния. EnvironmentReport содержит только status=ok и первые два значения. S3Settings хранит endpoint_url, region подписи, access_key, secret_key; два последних исключены из repr.

| Переменная | По умолчанию | Проверка |
|---|---|---|
| CLOUD_AUDIT_ENV | development | Допустимая среда |
| CLOUD_AUDIT_LOG_LEVEL | INFO | Допустимый уровень |
| CLOUD_AUDIT_STATE_DIR | .state | Непустой путь |
| CLOUD_AUDIT_S3_ENDPOINT_URL | https://hb.ru-msk.vkcloud-storage.ru | HTTPS, без credentials/query/fragment, путь пустой или /, порт 443/не указан |
| CLOUD_AUDIT_S3_REGION | us-east-1 | Непустой регион подписи, не обозначение физического расположения |
| AWS_ACCESS_KEY_ID | Нет | Явное непустое значение для сетевого vk |
| AWS_SECRET_ACCESS_KEY | Нет | Явное непустое значение для сетевого vk |

CLI объединяет локальный `.env` с процессным окружением, которому отдаёт приоритет; сам load_settings принимает уже готовый mapping. Загрузчик не исполняет shell и не изменяет os.environ. boto3 получает ключи явно, без поиска metadata/AWS-профиля. Настройки подключения общие для бакетов; имени бакета в окружении нет. S3Settings нельзя сериализовать и передавать как отчёт: repr=False защищает только строковое представление.

## Политика аудита

AuditPolicy — желаемый контекст, а не текущая облачная политика. `--policy PATH` принимает UTF-8 JSON до 64 КиБ; неизвестные поля и неверные типы отклоняются. Пример — `audit-policy.example.json`.

| Поле | Смысл |
|---|---|
| data_sensitivity | unknown/low/medium/high, влияет на impact |
| required_controls | versioning и/или acl_disabled; по умолчанию только versioning |
| trusted_project_ids | Собственные/доверенные проекты для классификации именованных субъектов |
| allowed_external_accounts | Явно разрешённые внешние subject или проектные идентификаторы |
| required_permissions | PermissionRequirement для каждого уникального subject и списка operations |
| exceptions | RuleException для уникальной пары resource_id/rule_id |

PermissionRequirement.subject — точный субъект; operations — подмножество read/list/write/delete/read_acl/write_acl/read_policy. Пустой массив означает «не нужны никакие операции», а отсутствие baseline не позволяет установить минимальность прав. Дубликаты subject запрещены, повторы операций удаляются.

RuleException требует непустые resource_id, rule_id, reason. expires_at необязателен, но должен иметь timezone. Срок не скрывает и не меняет риск находки. Неизвестные ID исключений проверяет движок относительно реестра.

## Снимок

ConfigurationSnapshot:

- id — uuid4 hex (32 строчных шестнадцатеричных символа); schema_version — 1 либо 2; provider — vk.
- resource — бакет; collected_at — начало последовательного сбора, не атомарная точка состояния облака.
- scope — bucket_configuration_only либо bucket_and_selected_objects; object_keys — точный выбранный набор (только v2).
- observations — уникальные ConfigurationObservation; обязательны восемь настроек и ACL каждого выбранного ключа. Допустимы согласованные имена anonymous-проб.
- collection_status — complete_for_scope, если все нужные факты available/absent и пробы определены без ошибки уборки; иначе partial.
- limitations — строго заданные ограничения версии/охвата, включая отсутствие полного IAM и неатомарность; resource_namespace — endpoint из провайдера либо None для старых/неизвестных данных.

ConfigurationObservation.name — имя настройки, `object_acl:KEY`, `anonymous_read:KEY` либо anonymous_list/write/delete. source — точный метод API; status — available/absent/access_denied/unsupported/error/not_found; data — нормализованный dict либо None; reason — безопасная категория недоступности, а не исходное сообщение SDK.

Для available reason=None. Для других статусов data=None и разрешённая причина: not_configured, permission_required, api_not_supported, resource_not_found либо rate_limit/service_error/sdk_or_network_error/invalid_response.

Проба хранится как available-наблюдение с outcome allowed/denied/not_found/error, http_status, checked_at и при необходимости object_key/cleanup_failed. Таким образом, available пробы не означает разрешённый доступ; collection_complete отдельно проверяет её outcome.

CollectionOptions хранит object_keys, probe_anonymous и allow_write_probes, проверяет до 20 уникальных ключей и необходимость unsigned-флага перед записью.

## Находка и риск

Evidence хранит field/source/observation_status и value: строку, JSON-строку нормализованных фактов или None. Тела пользовательских файлов и SDK ResponseMetadata не включаются.

Finding содержит rule_id, один из пяти статусов, explanation, кортеж evidence, RiskAssessment, recommendation, verification, optional exception_reason и limitations. Исключение допустимо только у нарушения/риска. Доказательства обязательны, кроме not_applicable.

RiskAssessment: level, score, likelihood, impact, rationale, affected_operations, model_version=1. Для insufficient_data level=unknown, числовые поля null. Для passed/n/a — none/0/0/0. Для находок score=likelihood×impact, согласованный уровень. Методика и границы — [SCANNING.md](SCANNING.md).

## Настоящий отчёт

SecurityReport включает:

- id, schema_version, mode=vk, resource;
- snapshot_id и snapshot_collected_at для входного факта, evaluated_at для времени интерпретации;
- scope/object_keys, limitations, collection_status;
- evaluation_status=complete/incomplete независимо от частичности посторонних настроек;
- полную AuditPolicy и results: Finding;
- ruleset_version и resource_namespace для сравнимости.

Новые отчёты имеют schema_version=3 и CURRENT_RULESET_VERSION='1'. v1 читается без новых полей, v2 — с объектным охватом/ограничениями; неизвестный provenance не заполняется из текущего подключения. Смена смысла правил требует повышения ruleset_version; переименование Python-модулей её не меняет.

Report decoder проверяет форму, время с timezone, риск, статусы, обязательные доказательства и согласованность версионирования/Ownership Controls. Для confirmed anonymous нужна положительная unsigned-проба правильной операции; для read — выбранный ключ. Это проверка согласованности локальных данных, не цифровая подпись/подтверждение их подлинности.

Отчёт сохраняет evidence и policy, поэтому читается после удаления бакета или истечения TTL входного снимка. Complete не означает безопасность, нулевой риск или актуальность после момента сбора.

## История и сравнение

HistoryQuery: фильтры resource_id, rule_id, severity, finding_status, mode (vk по умолчанию, None — все), run_status, limit=50 (1..500), offset=0 (неотрицательный). Фильтры правила/опасности/статуса должны совпасть на одной строке run_rules.

HistoryEntry: id/mode/resource, observed_at либо None, recorded_at, run_status, selected_rules, полные status_counts, optional error_code/resource_namespace. Для настоящих отчётов recorded_at соответствует evaluated_at; для demo/failed — времени записи. Это не отдельное время импорта старого отчёта.

HistoryPage: entries и total совпадений до пагинации, limit/offset. Сортировка по observed_at или recorded_at, затем recorded_at и ID по убыванию. Фильтр не обрезает счётчики полного запуска.

FindingChange: rule_id, change, reason, before/after Finding либо None. Change — new/persisted/resolved/unchanged/unverified. ReportComparison хранит ID/ресурсы/время обоих отчётов, comparable/reasons, changes и два ComparisonContext (snapshot, namespace, версия, охват, политика и статусы). Comparable описывает общий контекст; отдельный результат всё ещё может быть unverified. Подробные условия переходов — [SCANNING.md](SCANNING.md).

## Файлы и база данных

```text
STATE_DIR/                    0700
  data/                       0700
    audit.sqlite3             0600
    snapshots/                0700
      SNAPSHOT_ID.json        0600
    REPORT_ID.json            прежний формат, чтение/fallback/импорт
    fixture-UUID.json         приватные сводки искусственного стенда
  logs/                       0700
```

LocalStateStorage изменяет права существующих root/data/logs на 0700. Поэтому нужен выделенный каталог, а не домашний или общий каталог. Файловое логирование не реализовано: стандартный logging выводится в stderr; logs подготовлен как часть состояния.

SQLite user_version=1:

| Таблица | Столбцы и назначение |
|---|---|
| runs | id PK, mode, resource_id/name, observed_at, recorded_at, run_status, parameters JSON, payload JSON/NULL, error_code |
| run_rules | run_id FK, rule_id, position, status, severity; PK(run_id,rule_id) |

Полный отчёт и строки правил сохраняются одной транзакцией. ID нельзя перезаписать другим payload; идентичный повтор идемпотентен. Лимит нового отчёта 32 МиБ. Foreign keys включены, ожидание блокировки пять секунд. Неизвестная версия/повреждённая БД не создаёт видимость пустой истории. Симлинк вместо основного файла БД отклоняется. Стандартная SQLite-журнализация, не отдельная распределённая БД/очередь.

Controlled failed-run хранит cloud_request_failed либо snapshot_storage_failed и метаданные цели/правил, без payload и находок. Начало ещё выполняющегося задания/аварийное завершение процесса не отслеживаются. Сравнение failed отклоняется.

При отсутствии ID в БД чтение допускает старый JSON fallback; это не импортирует его в историю. `import-reports` явно перебирает UUID-файлы, сохраняет источники, повторяется идемпотентно; повреждённые/конфликтующие ID идут в skipped. JsonReportRepository остаётся поддерживаемым адаптером для прежних данных и тестов, основной CLI пишет SQLite.

JsonSnapshotRepository проверяет схему и лимит 2 МиБ, пишет tempfile→fsync→replace. TTL — семь суток; просроченный get отклоняется, удаление происходит при следующем save, не фоново. Отчёты не имеют автоматического TTL.

Экспорт создаётся с O_EXCL/0600, не перезаписывает файл, выполняет fsync и удаляет незавершённый файл при ошибке. Фильтр отчёта помечается is_filtered_view/view_filters/full_result_count и не меняет хранимые данные/общую оценку. Markdown экранирует внешние значения и подбирает безопасное ограждение JSON.

## Совместимость после рефакторинга

CLI-команды, JSON-форматы, идентификаторы, пути состояния и SQLite-схема сохранены. Внутренние Python-import пути изменены, старые пакеты и реэкспортные заглушки удалены; локальные скрипты и тесты переведены на новые имена. Внешним скриптам, импортировавшим старые внутренние модули, требуется обновить import. Сохранённые данные импортов Python не содержат и миграции из-за переноса не требуют.

## Многоцелевой ScanRun v1

Контракты models/scanning.py и все их поля добавлены в CODE_REFERENCE. ScanTarget задаёт имя/известные ключи/политику/разрешения конкретного бакета; ProbeResult — только один unsigned-факт с HTTP/временем/эффектом и отдельной подготовкой/уборкой. ObjectDiscovery явно хранит source, keys, limit, complete/limited/failed и безопасную ошибку. ExternalResult объединяет пробы с анонимным охватом; BucketScanResult сохраняет внешние находки, внутренний статус/ID отчёта и обе границы охвата. ScanRun содержит UUID/schema_version/namespace/время/источник и полноту выбора/max_objects/authenticated, результаты бакетов и ошибки. Вычисляемый incomplete добавляется в CLI-представление, не хранится как независимое доверенное поле.

Сводки хранятся в STATE_DIR/data/scans/UUID.json (0700/0600, атомарно без перезаписи, до 32 МиБ). Декодер восстанавливает только заданные dataclass/tuple/скаляры, отклоняет неизвестные поля/версии/типы и несогласованные находки/риск относительно проб. Это не цифровая подпись. Ссылки на внутренние SecurityReport ведут в прежнюю SQLite, её схема не менялась. Полное описание новых параметров, кодов, остатков и схемы файла целей: [STAGED_SCAN.md](STAGED_SCAN.md).

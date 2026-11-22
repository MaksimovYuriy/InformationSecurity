# Установка, запуск и демонстрация

## Установка и обычный запуск

Python 3.12+, из корня репозитория. Один раз установи пакет и закреплённые зависимости:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -e .
```

Затем достаточно `./cloud-audit scan --buckets my-training-bucket`. Локальный launcher использует установленную `.venv/bin/cloud-audit` без активации и PYTHONPATH. При активированной `.venv` можно писать `cloud-audit ...`.

Существующий `.env` читается автоматически из текущего каталога, не исполняется shell. Окружение процесса приоритетнее, включая пустые значения. Поддерживаются однострочные KEY=value, export, кавычки/комментарии; подстановок переменных и команд нет. Не перезаписывай файл с ключами копией примера. Файл из другого места задаётся глобальным `--env-file PATH`, отключение — `--no-env-file`; флаги идут перед командой. Help/version файл не читают. Неверный файл выдаёт код 2 без значений секретов.

Пошаговый краткий сценарий — [MANUAL_TEST.md](MANUAL_TEST.md).

## Команды

Общий вид: `./cloud-audit COMMAND ...` (или `cloud-audit` в активной `.venv`). У каждой команды есть `--help`. По умолчанию вывод JSON.

| Команда | Назначение и параметры |
|---|---|
| check | Создать/проверить выделенные каталоги, вывести версию/статус/среду/уровень журнала |
| connection | Проверить подключение, `--profile demo|vk` (demo по умолчанию) |
| resources | Получить бакеты выбранного профиля, `--profile demo|vk` |
| collect | Свежий снимок, обязательный `--resource`, профиль только vk; `--objects KEY...`, флаги проб |
| snapshot SNAPSHOT_ID | Читать непросроченный снимок без сети |
| audit | Ровно один `--resource`/`--snapshot`; `--profile demo|vk`, `--rules ID...`, `--policy PATH`; для свежего vk — объекты/пробы |
| report REPORT_ID | Читать отчёт; `--rule ID`, `--severity LEVEL`, `--status STATUS` |
| history | История; `--resource`, `--rule`, `--severity`, `--status`, `--profile vk|demo|all`, `--run-status`, `--limit`, `--offset` |
| compare BEFORE_ID AFTER_ID | Сравнить два полных настоящих отчёта, без сетевых запросов |
| import-reports | Явно включить прежние UUID-JSON в SQLite, сохранить источники |

Для команд, кроме check, доступен `--format json|text`. Для report/history/compare также `markdown` и `--output NEW_PATH`. Файл не перезаписывается. JSON/Markdown подходят для экспорта; при сочетании `--format text --output` сохраняется JSON, а не текстовая шапка stdout.

Severity: none/unknown/low/medium/high/critical. Status: confirmed_violation/potential_risk/passed/insufficient_data/not_applicable/simulated. Run status: complete/incomplete/failed/demo. History по умолчанию показывает vk, limit=50, максимум 500. Report-фильтр не меняет общую оценку; пустое представление не доказывает отсутствие находок в полном отчёте.

## Ступенчатый scan

Для нескольких бакетов и режима без ключей используйте [STAGED_SCAN.md](STAGED_SCAN.md): scan --buckets/--targets/--all-buckets, scan-report, отдельные разрешения мутаций. Следующий раздел описывает сохранённый одиночный audit.

## Реальный аудит

```bash
./cloud-audit connection --profile vk
./cloud-audit resources --profile vk
./cloud-audit audit --profile vk --resource BUCKET_NAME --objects synthetic.txt --probe-anonymous
```

Выберите искусственный объект, который разрешено проверять. По умолчанию выполняются все восемь правил. Ограничить выбор:

```bash
./cloud-audit audit --profile vk --resource BUCKET_NAME --objects synthetic.txt --probe-anonymous --rules anonymous-read anonymous-list --policy audit-policy.example.json
```

Пример политики нужно заменить фактическим контекстом: собственные проекты, разрешённые внешние субъекты, необходимые операции, чувствительность и исключения. Текущие права автоматически не считаются необходимыми.

`--probe-anonymous` делает ограниченные unsigned read/list. Запись/удаление выключены: для них требуются оба флага `--probe-anonymous --allow-write-probes`, отсутствие Object Lock и права уборки. Полные ограничения и алгоритмы — [SCANNING.md](SCANNING.md).

## Повторная оценка и отчёты

Из ответа audit возьмите report.id, snapshot_id. По сохранённому снимку без ключей:

```bash
./cloud-audit audit --profile vk --snapshot SNAPSHOT_ID --policy audit-policy.example.json
./cloud-audit report REPORT_ID --format markdown --output report.md
./cloud-audit history --resource BUCKET_NAME --severity high
./cloud-audit compare BEFORE_ID AFTER_ID --format markdown --output comparison.md
```

Офлайн-аудит повторяет интерпретацию сохранённых фактов и проб, не запускает новую сеть. Чтобы доказать исправление, нужен свежий сбор после ручного изменения. Для подтверждённого анонимного доступа сравнение требует нового отказа на тех же целях. Находка в принятом исключении остаётся находкой.

## Демонстрация без облака

```bash
./cloud-audit resources --profile demo
./cloud-audit audit --profile demo --resource demo-public
```

Demo использует два фиксированных ресурса и demo-public-read. Результаты simulated; это проверка запуска/сохранения, не доказательство сканирования облака.

## Воспроизводимый учебный стенд

После настройки локальных ключей:

```bash
PYTHONPATH=src .venv/bin/python scripts/verify_public_access.py --run-training-fixture
```

Флаг явно включает создание нового случайного бакета и искусственного файла. Скрипт проходит private→public read/list→private, сохраняет снимки/отчёты в `.state/data`, в finally пытается закрыть и удалить только созданные ресурсы. Использует фиксированный корень `.state` относительно текущего каталога, а не CLOUD_AUDIT_STATE_DIR. Нужны права создания/политики/удаления учебного стенда сверх обычного чтения аудитора. После смены политики каждая стадия получает до пяти свежих наблюдений с паузами секунду: read/list могут становиться доступными не одновременно. Все попытки сохраняются в stages, stage_count считает разные стадии, attempt_count — все наблюдения. Ожидание ограничено и не меняет ожидаемые статусы. Успех — success=true, cleanup_ok=true, exit 0. При ошибке — exit 2; сохранённую summary нужно проверить, в том числе cleanup_ok. Публичные write/delete не включает.

Для защиты покажите три отчёта, unsigned outcome, рекомендации, ручное исправление в описании сценария и compare открытого/закрытого запусков. В скрипте учебное исправление выполняется самим стендовым кодом; обычный аудитор настройки не изменяет. Примеры подтверждённых запусков: [ITERATION_09.md](ITERATION_09.md).

## Коды завершения и ошибки

| Код | Значение |
|---|---|
| 0 | Команда выполнена; нарушения сами по себе не делают команду неуспешной |
| 1 | Ошибка доступа к локальному состоянию/БД/экспорту |
| 2 | Неверные аргументы/настройки/ID, облачный запрос, отсутствующий или повреждённый отчёт; compare demo/failed |
| 3 | Частичный снимок, неполная оценка, несопоставимое/unverified сравнение или skipped при импорте |

Проверяйте scope, limitations и статусы отдельных правил. Неподдерживаемый API или отсутствующая baseline — не свидетельство безопасности. Предусмотренные ошибки выводятся без traceback/исходных сообщений SDK; stderr не содержит ключей. Логи SDK подавлены до CRITICAL.

## Состояние и перенос

Используйте выделенный CLOUD_AUDIT_STATE_DIR: приложение устанавливает права каталогов 0700. SQLite и экспорты содержат политики/идентификаторы, хотя ключей в них нет. Снимки хранятся семь суток, отчёты без TTL.

Для простой файловой резервной копии остановите процессы приложения, скопируйте весь каталог состояния в приватное место; `.env` храните отдельно. Для переноса укажите новый корень состояния. Перенос Python-модулей в итерации 10 миграции SQLite/JSON не требует. Источники прежнего JSON при импорте не удаляются.

Тесты, расширение и карта документации: [TESTING.md](TESTING.md), [ARCHITECTURE.md](ARCHITECTURE.md), [README.md](README.md).

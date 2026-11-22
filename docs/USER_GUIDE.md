# Установка, запуск и демонстрация

## Установка из исходников

Нужен Python 3.12+, доступ к пакетам при установке и к S3 endpoint при живом сканировании. Запуск из корня репозитория:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
PYTHONPATH=src .venv/bin/python -m cloud_audit check
PYTHONPATH=src .venv/bin/python -m cloud_audit --version
```

`requirements.txt` фиксирует проверенные runtime-зависимости; `pyproject.toml` содержит метаданные пакета, setuptools и консольную точку входа cloud-audit. Документированный базовый сценарий работает из исходников, не требует предварительной установки самого пакета.

Если `.env` ещё нет, создайте его из `.env.example`. Если ключи уже заполнены, переносите только необходимые новые поля, не перезаписывайте файл. Установите права `chmod 600 .env`, заполните AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY. Для загрузки доверенного shell-совместимого файла:

```bash
set -a
. ./.env
set +a
```

Shell исполняет содержимое файла; приложение автоматически его не читает. Секреты не следует передавать в чат, Git, отчёты и командную строку. Endpoint/регион общие для всех бакетов. Для офлайн-команд и demo ключи не нужны.

## Команды

Общий вид: `PYTHONPATH=src .venv/bin/python -m cloud_audit COMMAND ...`. У каждой команды есть `--help`. По умолчанию вывод JSON.

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

## Реальный аудит

```bash
PYTHONPATH=src .venv/bin/python -m cloud_audit connection --profile vk
PYTHONPATH=src .venv/bin/python -m cloud_audit resources --profile vk
PYTHONPATH=src .venv/bin/python -m cloud_audit audit --profile vk --resource BUCKET_NAME --objects synthetic.txt --probe-anonymous
```

Выберите искусственный объект, который разрешено проверять. По умолчанию выполняются все восемь правил. Ограничить выбор:

```bash
PYTHONPATH=src .venv/bin/python -m cloud_audit audit --profile vk --resource BUCKET_NAME --objects synthetic.txt --probe-anonymous --rules anonymous-read anonymous-list --policy audit-policy.example.json
```

Пример политики нужно заменить фактическим контекстом: собственные проекты, разрешённые внешние субъекты, необходимые операции, чувствительность и исключения. Текущие права автоматически не считаются необходимыми.

`--probe-anonymous` делает ограниченные unsigned read/list. Запись/удаление выключены: для них требуются оба флага `--probe-anonymous --allow-write-probes`, отсутствие Object Lock и права уборки. Полные ограничения и алгоритмы — [SCANNING.md](SCANNING.md).

## Повторная оценка и отчёты

Из ответа audit возьмите report.id, snapshot_id. По сохранённому снимку без ключей:

```bash
PYTHONPATH=src .venv/bin/python -m cloud_audit audit --profile vk --snapshot SNAPSHOT_ID --policy audit-policy.example.json
PYTHONPATH=src .venv/bin/python -m cloud_audit report REPORT_ID --format markdown --output report.md
PYTHONPATH=src .venv/bin/python -m cloud_audit history --resource BUCKET_NAME --severity high
PYTHONPATH=src .venv/bin/python -m cloud_audit compare BEFORE_ID AFTER_ID --format markdown --output comparison.md
```

Офлайн-аудит повторяет интерпретацию сохранённых фактов и проб, не запускает новую сеть. Чтобы доказать исправление, нужен свежий сбор после ручного изменения. Для подтверждённого анонимного доступа сравнение требует нового отказа на тех же целях. Находка в принятом исключении остаётся находкой.

## Демонстрация без облака

```bash
PYTHONPATH=src .venv/bin/python -m cloud_audit resources --profile demo
PYTHONPATH=src .venv/bin/python -m cloud_audit audit --profile demo --resource demo-public
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

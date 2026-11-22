# Итерация 9: испытания локального сервиса

## Статус и объём

Завершена в согласованном объёме: новые приёмочные проверки, матрица восьми правил, реальный изолированный VK Cloud и воспроизводимые CLI-сценарии. По прямому указанию пользователя выполнялись только новые тесты итерации 9. Полный регрессионный прогон перенесён в итерацию 10 и не заявляется выполненным.

Код ядра и контракты не изменялись. Добавлены `tests/test_iteration09_acceptance.py` и `scripts/run_iteration09.py`. Матрица и сопоставление исходному заданию — [ACCEPTANCE_MATRIX.md](ACCEPTANCE_MATRIX.md).

## Новый набор проверок

```bash
.venv/bin/python scripts/run_iteration09.py
# Либо без отдельного JSON-протокола:
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_iteration09_*.py' -v
```

Скрипт выбирает только `test_iteration09_*.py`, сохраняет приватный JSON с временем каждого метода и всего прогона, числом ошибок/падений и признаком full_suite_run=false. Источник тестовых снимков независим от прежних тестовых модулей. CLI запускается в отдельных процессах с явным PYTHONPATH и без AWS/S3-переменных. Опциональный `--output NEW_PATH` не перезаписывает файл.

Прогон в рабочем окружении: **8 методов, 0 ошибок, 0 падений, 5,405 с** по unittest (включает 24 комбинации матрицы и дополнительные CLI-сценарии). Протокол: `.state/data/iteration09-tests-16631dedc9af4af282bf9c312b4daf65.json`.

При подготовке тестов первоначальный снимок был отвергнут строгой схемой: добавлены обязательные настройки и точные collection_limitations. Затем исправлены самостоятельная передача PYTHONPATH дочерним процессам и ожидаемый статус check (`ok`). Это исправления новых испытательных материалов; дефектов ядра, требующих изменения поведения, в этих сценариях не обнаружено. Прежние тесты не импортировались и не запускались.

## Проверка чистой установки

В отдельном `/tmp/cloud-audit-iteration09-venv` создано новое окружение Python 3.12.8, успешно выполнена установка всех закреплённых зависимостей из `requirements.txt`. `pip check` сообщил `No broken requirements found`. Рабочее `.venv` не менялось.

```bash
python3.12 -m venv /tmp/cloud-audit-iteration09-venv
/tmp/cloud-audit-iteration09-venv/bin/python -m pip install -r requirements.txt
/tmp/cloud-audit-iteration09-venv/bin/python -m pip check
/tmp/cloud-audit-iteration09-venv/bin/python scripts/run_iteration09.py
```

В чистом окружении те же восемь новых методов прошли: **0 ошибок, 0 падений, 6,567 с** по unittest. Включены check, CLI-аудит, чтение истории/отчёта и экспорт. Протокол `.state/data/iteration09-tests-e7702aa72f5e4ad18736b564a586b3e2.json`. Это проверка документированного запуска из исходников через PYTHONPATH, не установки пакета/консольной точки входа через pyproject.toml. Старые тесты и в чистом окружении не выполнялись.

## Реальная проверка, 22.11.2026

Использован существующий сценарий:

```bash
PYTHONPATH=src .venv/bin/python scripts/verify_public_access.py --run-training-fixture
```

Нужны стандартные переменные подключения из `.env.example`, загруженные локально в окружение; приложение не читает `.env` автоматически. Реальные ключи загружены вспомогательным локальным процессом, не выводились и не включались в контекст агента. Скрипт намеренно создаёт отдельный временный бакет и кратковременно разрешает read/list только искусственных данных, затем закрывает доступ и удаляет стенд. Существующий пользовательский бакет не изменяется. Публичные write/delete не включаются.

Бакет: `cloud-audit-lab-ffc5359afd354753980919d5c0200866`; файл `synthetic-read-fixture.txt`.

| Стадия | Отчёт | unsigned read/list | Результаты read/list |
|---|---|---|---|
| closed_before | a4ee9162691248fcb3915dbf6179b2f8 | denied/403 | passed |
| public_read_list | 5e668f0e96bb4433a2a9a2dcaeaca9d6 | allowed/2xx | confirmed_violation |
| closed_after | caadeed1101647ad87f703228e663bb3 | denied/403 | passed |

Весь сценарий, включая три сбора/аудита и уборку, занял **4,653 с**; success=true, cleanup_ok=true. Это один замер, не нагрузочный тест. Протоколы:

- `.state/data/iteration09-live-f30a9dfce128408ab00f3a3e29aaba47.json`;
- `.state/data/fixture-7b9489ca04794fc2b04ca213a3bd56db.json`.

Первая попытка в ограниченной сетевой среде не дошла до стадий аудита (stage_count=0, success=false, cleanup_ok=true); успешный запуск выполнен с разрешённым сетевым доступом. Неуспешная попытка не включается в доказательство работоспособности облака.

## История, сравнение и ошибки

Через CLI без ключей проверено:

- closed_before→public: new для read/list, write/delete unchanged; 0,085 с;
- public→closed_after: resolved для read/list с новыми отрицательными unsigned-пробами, write/delete unchanged; 0,094 с;
- Markdown сравнения создан с правами 0600, 0,096 с;
- полный набор восьми правил по сохранённому реальному снимку: 0,096 с, код 3 из-за insufficient_data для избыточности прав;
- история временного ресурса содержит три исходных отчёта и дополнительный офлайн-отчёт; 0,085 с.

Офлайн-отчёт: `209f3da9f33b4f8d80c8d5afd625686c`. Версионирование временного бакета выключено → confirmed_violation, ACL включены → potential_risk, нет baseline → excess insufficient_data. Read/list/write/delete и внешний доступ passed в пределах охвата. Исправление read/list не выдаётся за устранение всех иных рисков.

Артефакты:

- `.state/data/iteration09-workflow-0b0e9e80012e4797b1e642039c97db5e.json`;
- `.state/data/iteration09-comparison-5608e7851f294176b9b998c3da34835f.md`.

После удаления стенда реальный audit того же бакета вернул код 2, записал failed-run `2ec023f05b7a49dc85117c3f9cc4504a` без находок. Compare с публичным отчётом тоже вернул 2, без отчёта об устранении. Проверка заняла 1,225 с. Протокол `.state/data/iteration09-failure-9a4ab13f85a9435081d65be47d573e82.json`.

## Воспроизведение локального сравнения

Для сохранённых в этой рабочей среде отчётов:

```bash
PYTHONPATH=src .venv/bin/python -m cloud_audit history --resource cloud-audit-lab-ffc5359afd354753980919d5c0200866
PYTHONPATH=src .venv/bin/python -m cloud_audit compare a4ee9162691248fcb3915dbf6179b2f8 5e668f0e96bb4433a2a9a2dcaeaca9d6
PYTHONPATH=src .venv/bin/python -m cloud_audit compare 5e668f0e96bb4433a2a9a2dcaeaca9d6 caadeed1101647ad87f703228e663bb3 --format markdown
```

Артефакты `.state` не входят в Git; на другом компьютере нужно выполнить новый стендовый сценарий и подставить его ID. TTL входных снимков — семь суток, отчёты для чтения/сравнения сохраняются без TTL. Указанный удалённый бакет не нужно создавать повторно вручную.

## Следующий этап

Итерация 10: полный регрессионный прогон всех тестов, документация основного сервиса, необходимый рефакторинг и демонстрация. ИИ-помощник, включая выбор Cloud.ru/MCP/Docker, остаётся итерацией 11. Сервер и API в этой итерации не добавлялись.

# Полный справочник исходного кода

Справочник включает каждый Python-модуль приложения и каждый поддерживаемый скрипт, все явно объявленные классы, функции, методы, поля моделей и константы. Он строится из фактического AST и docstring; импорт модулей и обращение к облаку не выполняются. Локальные переменные и lambda описываются алгоритмом содержащего метода.

Причины архитектурных решений: [ARCHITECTURE.md](ARCHITECTURE.md). Модели и форматы: [DATA_CONTRACTS.md](DATA_CONTRACTS.md). Правила и порядок сканирования: [SCANNING.md](SCANNING.md).

Обновление: `.venv/bin/python scripts/build_code_reference.py`; проверка актуальности: добавить `--check`.

## `src/cloud_audit/__init__.py`

Единое приложение проверки безопасности облачного хранилища; источник версии пакета.

[Исходный файл](../src/cloud_audit/__init__.py)

Поле/константа `__version__`:

```python
__version__ = '0.1.0'
```

## `src/cloud_audit/__main__.py`

Запуск через python -m cloud_audit: передаёт управление CLI и возвращает его код завершения.

[Исходный файл](../src/cloud_audit/__main__.py)

Зависимости: `cloud_audit.cli`.

## `src/cloud_audit/cli.py`

Консольный интерфейс и сборка зависимостей: выбирает сценарий, создаёт адаптеры, выводит результат и
код завершения.

[Исходный файл](../src/cloud_audit/cli.py)

Зависимости: `argparse`, `dataclasses`, `json`, `logging`, `os`, `pathlib`, `cloud_audit`, `cloud_audit.errors`, `cloud_audit.services.profiles`, `cloud_audit.services.environment`, `cloud_audit.services.snapshots`, `cloud_audit.rules.engine`, `cloud_audit.services.audit`, `cloud_audit.rules.registry`, `cloud_audit.models.snapshot`, `cloud_audit.models.history`, `cloud_audit.models.security`, `cloud_audit.services.history`, `cloud_audit.configuration.policy`, `cloud_audit.configuration.dotenv`, `cloud_audit.configuration.environment`, `cloud_audit.providers.demo`, `cloud_audit.storage.json_reports`, `cloud_audit.storage.state`, `cloud_audit.storage.snapshots`, `cloud_audit.storage.sqlite`, `cloud_audit.reports.formatting`.

### Функция/метод `build_parser`

[Определение](../src/cloud_audit/cli.py#L36)

Описывает команды, взаимоисключающий выбор ресурса/снимка, форматы, фильтры и флаги проб;
--help/--version не требуют состояния.

```python
def build_parser() -> argparse.ArgumentParser
```

### Функция/метод `main`

[Определение](../src/cloud_audit/cli.py#L91)

Разбирает аргументы CLI, загружает настройки, собирает реализации интерфейсов, выполняет
выбранную команду и возвращает 0/1/2/3; секреты не выводит.

```python
def main() -> int
```

## `src/cloud_audit/configuration/__init__.py`

Загрузка и строгая проверка конфигурации.

[Исходный файл](../src/cloud_audit/configuration/__init__.py)

## `src/cloud_audit/configuration/dotenv.py`

Локальный .env как данные: без shell, подстановок и изменения окружения процесса.

[Исходный файл](../src/cloud_audit/configuration/dotenv.py)

Зависимости: `collections.abc`, `pathlib`, `re`, `cloud_audit.errors`.

Поле/константа `MAX_BYTES`:

```python
MAX_BYTES = 64 * 1024
```

### Функция/метод `parse_value`

[Определение](../src/cloud_audit/configuration/dotenv.py#L11)

Читает однострочное значение, кавычки и комментарий; $ и backtick остаются обычным текстом.

```python
def parse_value(raw: str) -> str
```

### Функция/метод `load_environment`

[Определение](../src/cloud_audit/configuration/dotenv.py#L38)

Объединяет один выбранный файл с окружением; существующие переменные, включая пустые, приоритетны.

```python
def load_environment(environment: Mapping[str, str], path: Path | None=Path('.env'), *, required=False) -> dict[str, str]
```

## `src/cloud_audit/configuration/environment.py`

Проверяет переменные окружения приложения и S3; отдельно загружает ключи только для сетевых команд.

[Исходный файл](../src/cloud_audit/configuration/environment.py)

Зависимости: `collections.abc`, `pathlib`, `urllib.parse`, `cloud_audit.models.settings`, `cloud_audit.errors`.

### Функция/метод `load_settings`

[Определение](../src/cloud_audit/configuration/environment.py#L10)

Проверяет допустимые ENV/LOG_LEVEL и непустой STATE_DIR; возвращает Settings без чтения .env.

```python
def load_settings(environment: Mapping[str, str]) -> Settings
```

### Функция/метод `load_s3_settings`

[Определение](../src/cloud_audit/configuration/environment.py#L24)

Проверяет HTTPS endpoint без credentials/пути/query, регион и непустые явные ключи; не выводит
введённые значения.

```python
def load_s3_settings(environment: Mapping[str, str]) -> S3Settings
```

### Функция/метод `load_scan_settings`

[Определение](../src/cloud_audit/configuration/environment.py#L52)

Разрешает отсутствие обоих ключей для scan; один ключ — ошибка, external-only явно игнорирует пару.

```python
def load_scan_settings(environment: Mapping[str, str], *, external_only=False)
```

## `src/cloud_audit/configuration/policy.py`

Загружает строгую политику аудита из JSON: чувствительность, обязательные контроли, доверие,
необходимые права и исключения.

[Исходный файл](../src/cloud_audit/configuration/policy.py)

Зависимости: `json`, `datetime`, `pathlib`, `cloud_audit.models.security`, `cloud_audit.errors`.

### Функция/метод `string_list`

[Определение](../src/cloud_audit/configuration/policy.py#L13)

Проверяет массив непустых строк и удаляет повторы с сохранением порядка; отклоняет null и словари.

```python
def string_list(value)
```

### Функция/метод `parse_audit_policy`

[Определение](../src/cloud_audit/configuration/policy.py#L20)

Проверяет типы, допустимые поля/операции, уникальные subject и исключения, timezone сроков;
строит AuditPolicy.

```python
def parse_audit_policy(data: dict) -> AuditPolicy
```

### Функция/метод `load_audit_policy`

[Определение](../src/cloud_audit/configuration/policy.py#L72)

При отсутствии пути возвращает базовую политику; иначе читает UTF-8 JSON до 64 КиБ и проверяет его.

```python
def load_audit_policy(path: Path | None=None) -> AuditPolicy
```

## `src/cloud_audit/configuration/targets.py`

Строгий файл целей: объекты и разрешения мутаций задаются отдельно для каждого бакета.

[Исходный файл](../src/cloud_audit/configuration/targets.py)

Зависимости: `json`, `pathlib`, `cloud_audit.configuration.policy`, `cloud_audit.errors`, `cloud_audit.models.scanning`.

### Функция/метод `parse_targets`

[Определение](../src/cloud_audit/configuration/targets.py#L10)

Проверяет поля, типы и уникальность до любых сетевых запросов; ключи доступа здесь запрещены.

```python
def parse_targets(data)
```

### Функция/метод `load_targets`

[Определение](../src/cloud_audit/configuration/targets.py#L31)

Читает UTF-8 JSON до 256 КиБ без исполнения содержимого.

```python
def load_targets(path: Path)
```

## `src/cloud_audit/errors.py`

Контролируемые ошибки запроса и конфигурации; сообщения не должны раскрывать ключи и исходные ответы
SDK.

[Исходный файл](../src/cloud_audit/errors.py)

### Класс `AuditError`

[Определение](../src/cloud_audit/errors.py#L7)

Invalid audit request, unavailable resource or inconsistent saved evidence.

Базовые классы: `ValueError`.

### Класс `ConfigurationError`

[Определение](../src/cloud_audit/errors.py#L11)

Invalid configuration; messages never include supplied values.

Базовые классы: `ValueError`.

## `src/cloud_audit/interfaces.py`

Контракты внедряемых провайдеров, репозиториев и правил. Описывают необходимые операции без
зависимости от boto3, SQLite и CLI.

[Исходный файл](../src/cloud_audit/interfaces.py)

Зависимости: `typing`, `cloud_audit.models.resources`, `cloud_audit.models.security`, `cloud_audit.models.snapshot`, `cloud_audit.models.history`, `cloud_audit.models.scanning`.

### Класс `StorageProvider`

[Определение](../src/cloud_audit/interfaces.py#L14)

Интерфейс подключения и перечисления ресурсов; не содержит имитации или облачной логики правил.

Базовые классы: `Protocol`.

Поле/константа `StorageProvider.mode`:

```python
mode: str
```

Поле/константа `StorageProvider.connection_message`:

```python
connection_message: str
```

### Функция/метод `StorageProvider.connect`

[Определение](../src/cloud_audit/interfaces.py#L18)

Контракт операции connect; реализация передаётся извне. Типы аргументов и результата
определяют ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def connect(self) -> None
```

### Функция/метод `StorageProvider.resources`

[Определение](../src/cloud_audit/interfaces.py#L24)

Контракт операции resources; реализация передаётся извне. Типы аргументов и результата
определяют ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def resources(self) -> tuple[Resource, ...]
```

### Класс `SimulationProvider`

[Определение](../src/cloud_audit/interfaces.py#L32)

Дополнительный контракт preview только для демонстрационного профиля.

Базовые классы: `StorageProvider, Protocol`.

### Функция/метод `SimulationProvider.preview`

[Определение](../src/cloud_audit/interfaces.py#L34)

Контракт операции preview; реализация передаётся извне. Типы аргументов и результата
определяют ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def preview(self, resource: Resource, rules: tuple[str, ...]) -> tuple[RuleResult, ...]
```

### Класс `ReportRepository`

[Определение](../src/cloud_audit/interfaces.py#L42)

Контракт сохранения и чтения demo или настоящего отчёта.

Базовые классы: `Protocol`.

### Функция/метод `ReportRepository.save`

[Определение](../src/cloud_audit/interfaces.py#L44)

Контракт операции save; реализация передаётся извне. Типы аргументов и результата определяют
ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def save(self, report: AuditReport | SecurityReport) -> None
```

### Функция/метод `ReportRepository.get`

[Определение](../src/cloud_audit/interfaces.py#L50)

Контракт операции get; реализация передаётся извне. Типы аргументов и результата определяют
ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def get(self, report_id: str) -> AuditReport | SecurityReport
```

### Класс `SecurityReportRepository`

[Определение](../src/cloud_audit/interfaces.py#L58)

Минимальный контракт записи настоящего отчёта для сервиса аудита.

Базовые классы: `Protocol`.

### Функция/метод `SecurityReportRepository.save`

[Определение](../src/cloud_audit/interfaces.py#L60)

Контракт операции save; реализация передаётся извне. Типы аргументов и результата определяют
ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def save(self, report: SecurityReport) -> None
```

### Класс `AuditHistoryRepository`

[Определение](../src/cloud_audit/interfaces.py#L68)

Контракт чтения полных отчётов и страниц истории.

Базовые классы: `Protocol`.

### Функция/метод `AuditHistoryRepository.get`

[Определение](../src/cloud_audit/interfaces.py#L70)

Контракт операции get; реализация передаётся извне. Типы аргументов и результата определяют
ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def get(self, report_id: str) -> AuditReport | SecurityReport
```

### Функция/метод `AuditHistoryRepository.history`

[Определение](../src/cloud_audit/interfaces.py#L76)

Контракт операции history; реализация передаётся извне. Типы аргументов и результата
определяют ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def history(self, query: HistoryQuery) -> HistoryPage
```

### Класс `StateStorage`

[Определение](../src/cloud_audit/interfaces.py#L84)

Контракт подготовки локального состояния, допускающий другую реализацию.

Базовые классы: `Protocol`.

### Функция/метод `StateStorage.prepare`

[Определение](../src/cloud_audit/interfaces.py#L86)

Контракт операции prepare; реализация передаётся извне. Типы аргументов и результата
определяют ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def prepare(self) -> None
```

### Класс `ConfigurationCollector`

[Определение](../src/cloud_audit/interfaces.py#L94)

Контракт получения нормализованных наблюдений выбранного ресурса.

Базовые классы: `Protocol`.

Поле/константа `ConfigurationCollector.mode`:

```python
mode: str
```

### Функция/метод `ConfigurationCollector.collect`

[Определение](../src/cloud_audit/interfaces.py#L97)

Контракт операции collect; реализация передаётся извне. Типы аргументов и результата
определяют ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def collect(self, resource: Resource, options: CollectionOptions | None=None) -> tuple[ConfigurationObservation, ...]
```

### Класс `SnapshotRepository`

[Определение](../src/cloud_audit/interfaces.py#L105)

Контракт сохранения и чтения снимка по идентификатору.

Базовые классы: `Protocol`.

### Функция/метод `SnapshotRepository.save`

[Определение](../src/cloud_audit/interfaces.py#L107)

Контракт операции save; реализация передаётся извне. Типы аргументов и результата определяют
ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def save(self, snapshot: ConfigurationSnapshot) -> None
```

### Функция/метод `SnapshotRepository.get`

[Определение](../src/cloud_audit/interfaces.py#L113)

Контракт операции get; реализация передаётся извне. Типы аргументов и результата определяют
ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def get(self, snapshot_id: str) -> ConfigurationSnapshot
```

### Класс `SecurityRule`

[Определение](../src/cloud_audit/interfaces.py#L121)

Контракт правила: ID, обязательные данные, применимость, алгоритм, рекомендация и подтверждение.

Базовые классы: `Protocol`.

Поле/константа `SecurityRule.id`:

```python
id: str
```

Поле/константа `SecurityRule.required_data`:

```python
required_data: tuple[str, ...]
```

Поле/константа `SecurityRule.recommendation`:

```python
recommendation: str
```

Поле/константа `SecurityRule.verification`:

```python
verification: str
```

### Функция/метод `SecurityRule.applicable`

[Определение](../src/cloud_audit/interfaces.py#L127)

Проверяет поддерживаемый scope снимка; при неприменимости движок формирует not_applicable
без выполнения алгоритма.

```python
def applicable(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> bool
```

### Функция/метод `SecurityRule.evaluate`

[Определение](../src/cloud_audit/interfaces.py#L133)

Контракт операции evaluate; реализация передаётся извне. Типы аргументов и результата
определяют ожидаемые данные, тело Protocol не выполняет интеграцию.

```python
def evaluate(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> Finding
```

### Класс `ExternalInspection`

[Определение](../src/cloud_audit/interfaces.py#L141)

Внешняя проверка через unsigned-клиент и ограниченное чтение дополнительно найденных объектов.

Базовые классы: `Protocol`.

Поле/константа `ExternalInspection.namespace`:

```python
namespace: str
```

### Функция/метод `ExternalInspection.inspect`

[Определение](../src/cloud_audit/interfaces.py#L145)

Возвращает факты выбранных операций и охват списка, без внутреннего аудита.

```python
def inspect(self, target: ScanTarget, limit: int) -> ExternalResult
```

### Функция/метод `ExternalInspection.read_objects`

[Определение](../src/cloud_audit/interfaces.py#L149)

Проверяет новые ключи, не повторяя запись/удаление или список.

```python
def read_objects(self, bucket: str, keys: tuple[str, ...]) -> tuple[ProbeResult, ...]
```

### Класс `ScanRunRepository`

[Определение](../src/cloud_audit/interfaces.py#L154)

Сохранение и чтение самодостаточного многоцелевого запуска.

Базовые классы: `Protocol`.

### Функция/метод `ScanRunRepository.save`

[Определение](../src/cloud_audit/interfaces.py#L156)

Публикует неизменяемую сводку по ID.

```python
def save(self, run: ScanRun) -> None
```

### Функция/метод `ScanRunRepository.get`

[Определение](../src/cloud_audit/interfaces.py#L160)

Возвращает проверенную сводку без подключения к облаку.

```python
def get(self, identifier: str) -> ScanRun
```

### Класс `ScanProvider`

[Определение](../src/cloud_audit/interfaces.py#L165)

Авторизованный провайдер выбора бакетов, настроек и ограниченных ключей объектов.

Базовые классы: `StorageProvider, ConfigurationCollector, Protocol`.

### Функция/метод `ScanProvider.discover_objects`

[Определение](../src/cloud_audit/interfaces.py#L167)

Возвращает явный полный/ограниченный/ошибочный охват объектов.

```python
def discover_objects(self, bucket: str, limit: int) -> ObjectDiscovery
```

## `src/cloud_audit/models/__init__.py`

Модели данных приложения без сетевых и файловых операций.

[Исходный файл](../src/cloud_audit/models/__init__.py)

## `src/cloud_audit/models/history.py`

Запросы и страницы истории, контексты сравнения и объяснимые переходы результатов правил.

[Исходный файл](../src/cloud_audit/models/history.py)

Зависимости: `dataclasses`, `cloud_audit.models.resources`, `cloud_audit.models.security`.

### Класс `HistoryQuery`

[Определение](../src/cloud_audit/models/history.py#L9)

Неизменяемые фильтры истории; limit/offset проверяются реализацией репозитория.

Поле/константа `HistoryQuery.resource_id`:

```python
resource_id: str | None = None
```

Поле/константа `HistoryQuery.rule_id`:

```python
rule_id: str | None = None
```

Поле/константа `HistoryQuery.severity`:

```python
severity: str | None = None
```

Поле/константа `HistoryQuery.finding_status`:

```python
finding_status: str | None = None
```

Поле/константа `HistoryQuery.mode`:

```python
mode: str | None = 'vk'
```

Поле/константа `HistoryQuery.run_status`:

```python
run_status: str | None = None
```

Поле/константа `HistoryQuery.limit`:

```python
limit: int = 50
```

Поле/константа `HistoryQuery.offset`:

```python
offset: int = 0
```

### Класс `HistoryEntry`

[Определение](../src/cloud_audit/models/history.py#L22)

Краткая запись запуска с выбранными правилами, полными счётчиками статусов и безопасной
категорией ошибки.

Поле/константа `HistoryEntry.id`:

```python
id: str
```

Поле/константа `HistoryEntry.mode`:

```python
mode: str
```

Поле/константа `HistoryEntry.resource`:

```python
resource: Resource
```

Поле/константа `HistoryEntry.observed_at`:

```python
observed_at: str | None
```

Поле/константа `HistoryEntry.recorded_at`:

```python
recorded_at: str
```

Поле/константа `HistoryEntry.run_status`:

```python
run_status: str
```

Поле/константа `HistoryEntry.selected_rules`:

```python
selected_rules: tuple[str, ...]
```

Поле/константа `HistoryEntry.status_counts`:

```python
status_counts: dict[str, int]
```

Поле/константа `HistoryEntry.error_code`:

```python
error_code: str | None = None
```

Поле/константа `HistoryEntry.resource_namespace`:

```python
resource_namespace: str | None = None
```

### Класс `HistoryPage`

[Определение](../src/cloud_audit/models/history.py#L40)

Страница записей и общее число совпадений до пагинации.

Поле/константа `HistoryPage.entries`:

```python
entries: tuple[HistoryEntry, ...]
```

Поле/константа `HistoryPage.total`:

```python
total: int
```

Поле/константа `HistoryPage.limit`:

```python
limit: int
```

Поле/константа `HistoryPage.offset`:

```python
offset: int
```

### Класс `FindingChange`

[Определение](../src/cloud_audit/models/history.py#L49)

Переход одного rule_id: before/after, классификация изменения и объяснение.

Поле/константа `FindingChange.rule_id`:

```python
rule_id: str
```

Поле/константа `FindingChange.change`:

```python
change: str
```

Поле/константа `FindingChange.reason`:

```python
reason: str
```

Поле/константа `FindingChange.before`:

```python
before: Finding | None
```

Поле/константа `FindingChange.after`:

```python
after: Finding | None
```

### Класс `ComparisonContext`

[Определение](../src/cloud_audit/models/history.py#L59)

Контекст одного сравниваемого отчёта: снимок, endpoint, версия правил, охват, политика и полнота.

Поле/константа `ComparisonContext.snapshot_id`:

```python
snapshot_id: str
```

Поле/константа `ComparisonContext.resource_namespace`:

```python
resource_namespace: str | None
```

Поле/константа `ComparisonContext.ruleset_version`:

```python
ruleset_version: str | None
```

Поле/константа `ComparisonContext.scope`:

```python
scope: str
```

Поле/константа `ComparisonContext.object_keys`:

```python
object_keys: tuple[str, ...]
```

Поле/константа `ComparisonContext.policy`:

```python
policy: AuditPolicy
```

Поле/константа `ComparisonContext.collection_status`:

```python
collection_status: str
```

Поле/константа `ComparisonContext.evaluation_status`:

```python
evaluation_status: str
```

### Класс `ReportComparison`

[Определение](../src/cloud_audit/models/history.py#L72)

Полное сравнение двух отчётов: идентичность, время, сопоставимость, причины и переходы.

Поле/константа `ReportComparison.before_id`:

```python
before_id: str
```

Поле/константа `ReportComparison.after_id`:

```python
after_id: str
```

Поле/константа `ReportComparison.before_resource`:

```python
before_resource: Resource
```

Поле/константа `ReportComparison.after_resource`:

```python
after_resource: Resource
```

Поле/константа `ReportComparison.before_observed_at`:

```python
before_observed_at: str
```

Поле/константа `ReportComparison.after_observed_at`:

```python
after_observed_at: str
```

Поле/константа `ReportComparison.comparable`:

```python
comparable: bool
```

Поле/константа `ReportComparison.reasons`:

```python
reasons: tuple[str, ...]
```

Поле/константа `ReportComparison.changes`:

```python
changes: tuple[FindingChange, ...]
```

Поле/константа `ReportComparison.before_context`:

```python
before_context: ComparisonContext
```

Поле/константа `ReportComparison.after_context`:

```python
after_context: ComparisonContext
```

## `src/cloud_audit/models/resources.py`

Неизменяемые модели идентичности ресурса и совместимого демонстрационного отчёта.

[Исходный файл](../src/cloud_audit/models/resources.py)

Зависимости: `dataclasses`.

### Класс `Resource`

[Определение](../src/cloud_audit/models/resources.py#L6)

Идентификатор и отображаемое имя бакета; используется без объектов SDK.

Поле/константа `Resource.id`:

```python
id: str
```

Поле/константа `Resource.name`:

```python
name: str
```

### Класс `RuleResult`

[Определение](../src/cloud_audit/models/resources.py#L13)

Результат демонстрационного сценария: правило, simulated и пояснение.

Поле/константа `RuleResult.rule_id`:

```python
rule_id: str
```

Поле/константа `RuleResult.status`:

```python
status: str
```

Поле/константа `RuleResult.explanation`:

```python
explanation: str
```

### Класс `AuditReport`

[Определение](../src/cloud_audit/models/resources.py#L21)

Совместимый демонстрационный отчёт; не содержит настоящих обнаружений или оценки риска.

Поле/константа `AuditReport.id`:

```python
id: str
```

Поле/константа `AuditReport.mode`:

```python
mode: str
```

Поле/константа `AuditReport.resource`:

```python
resource: Resource
```

Поле/константа `AuditReport.results`:

```python
results: tuple[RuleResult, ...]
```

## `src/cloud_audit/models/scanning.py`

Цели и самодостаточный результат последовательной внешней/внутренней проверки бакетов.

[Исходный файл](../src/cloud_audit/models/scanning.py)

Зависимости: `dataclasses`, `datetime`, `re`, `cloud_audit.models.security`, `cloud_audit.models.snapshot`.

### Класс `ScanTarget`

[Определение](../src/cloud_audit/models/scanning.py#L11)

Отдельный бакет, известные объекты, контекст и явное разрешение мутаций/остатков.

Поле/константа `ScanTarget.name`:

```python
name: str
```

Поле/константа `ScanTarget.object_keys`:

```python
object_keys: tuple[str, ...] = ()
```

Поле/константа `ScanTarget.allow_mutations`:

```python
allow_mutations: bool = False
```

Поле/константа `ScanTarget.allow_residue`:

```python
allow_residue: bool = False
```

Поле/константа `ScanTarget.policy`:

```python
policy: AuditPolicy = field(default_factory=AuditPolicy)
```

### Функция/метод `ScanTarget.__post_init__`

[Определение](../src/cloud_audit/models/scanning.py#L19)

Проверяет имя S3-бакета, ограниченный охват и явные булевы разрешения.

```python
def __post_init__(self)
```

### Класс `ProbeResult`

[Определение](../src/cloud_audit/models/scanning.py#L29)

Факт одного unsigned-запроса; подготовка/уборка и проверка эффекта указаны отдельно.

Поле/константа `ProbeResult.operation`:

```python
operation: str
```

Поле/константа `ProbeResult.target`:

```python
target: str | None
```

Поле/константа `ProbeResult.outcome`:

```python
outcome: str
```

Поле/константа `ProbeResult.http_status`:

```python
http_status: int | None
```

Поле/константа `ProbeResult.checked_at`:

```python
checked_at: str
```

Поле/константа `ProbeResult.verification`:

```python
verification: str | None = None
```

Поле/константа `ProbeResult.preparation`:

```python
preparation: str = 'none'
```

Поле/константа `ProbeResult.cleanup`:

```python
cleanup: str = 'not_needed'
```

Поле/константа `ProbeResult.reason`:

```python
reason: str | None = None
```

### Функция/метод `ProbeResult.__post_init__`

[Определение](../src/cloud_audit/models/scanning.py#L41)

Отклоняет нераспознанные статусы, неверный HTTP и время без timezone.

```python
def __post_init__(self)
```

### Класс `ObjectDiscovery`

[Определение](../src/cloud_audit/models/scanning.py#L55)

Ограниченное перечисление объектов; limited/failed не означает полного охвата.

Поле/константа `ObjectDiscovery.keys`:

```python
keys: tuple[str, ...]
```

Поле/константа `ObjectDiscovery.status`:

```python
status: str
```

Поле/константа `ObjectDiscovery.source`:

```python
source: str
```

Поле/константа `ObjectDiscovery.limit`:

```python
limit: int
```

Поле/константа `ObjectDiscovery.error_code`:

```python
error_code: str | None = None
```

### Функция/метод `ObjectDiscovery.__post_init__`

[Определение](../src/cloud_audit/models/scanning.py#L63)

Проверяет предел перечисления и допустимые источник/статус.

```python
def __post_init__(self)
```

### Класс `ExternalResult`

[Определение](../src/cloud_audit/models/scanning.py#L73)

Набор независимых проб и охват анонимного списка, без облачных секретов.

Поле/константа `ExternalResult.probes`:

```python
probes: tuple[ProbeResult, ...]
```

Поле/константа `ExternalResult.discovery`:

```python
discovery: ObjectDiscovery
```

### Класс `BucketScanResult`

[Определение](../src/cloud_audit/models/scanning.py#L80)

Результаты двух этапов одного бакета, находки внешнего этапа и ссылка на внутренний отчёт.

Поле/константа `BucketScanResult.bucket`:

```python
bucket: str
```

Поле/константа `BucketScanResult.external_status`:

```python
external_status: str
```

Поле/константа `BucketScanResult.external`:

```python
external: ExternalResult | None
```

Поле/константа `BucketScanResult.external_findings`:

```python
external_findings: tuple[Finding, ...]
```

Поле/константа `BucketScanResult.internal_status`:

```python
internal_status: str
```

Поле/константа `BucketScanResult.internal_report_id`:

```python
internal_report_id: str | None
```

Поле/константа `BucketScanResult.internal_discovery`:

```python
internal_discovery: ObjectDiscovery | None
```

Поле/константа `BucketScanResult.errors`:

```python
errors: tuple[str, ...] = ()
```

Поле/константа `BucketScanResult.limitations`:

```python
limitations: tuple[str, ...] = ()
```

Поле/константа `BucketScanResult.target`:

```python
target: ScanTarget | None = None
```

### Функция/метод `BucketScanResult.__post_init__`

[Определение](../src/cloud_audit/models/scanning.py#L93)

Проверяет согласованность статусов этапов и ссылки на внутренний отчёт.

```python
def __post_init__(self)
```

### Класс `ScanRun`

[Определение](../src/cloud_audit/models/scanning.py#L101)

Общая сводка запуска с сохранёнными фактами каждого бакета и полнотой выбора целей.

Поле/константа `ScanRun.id`:

```python
id: str
```

Поле/константа `ScanRun.schema_version`:

```python
schema_version: int
```

Поле/константа `ScanRun.namespace`:

```python
namespace: str
```

Поле/константа `ScanRun.started_at`:

```python
started_at: str
```

Поле/константа `ScanRun.completed_at`:

```python
completed_at: str
```

Поле/константа `ScanRun.selection_source`:

```python
selection_source: str
```

Поле/константа `ScanRun.selection_status`:

```python
selection_status: str
```

Поле/константа `ScanRun.max_objects`:

```python
max_objects: int
```

Поле/константа `ScanRun.authenticated`:

```python
authenticated: bool
```

Поле/константа `ScanRun.buckets`:

```python
buckets: tuple[BucketScanResult, ...]
```

Поле/константа `ScanRun.errors`:

```python
errors: tuple[str, ...] = ()
```

### Функция/метод `ScanRun.__post_init__`

[Определение](../src/cloud_audit/models/scanning.py#L115)

Проверяет версию, ID, время, пределы, происхождение целей и уникальность бакетов.

```python
def __post_init__(self)
```

### Функция/метод `ScanRun.incomplete`

[Определение](../src/cloud_audit/models/scanning.py#L128)

Определяет частичность выбранных операций и охвата; выключенные мутации не считаются выполненными.

```python
def incomplete(self)
```

## `src/cloud_audit/models/security.py`

Неизменяемые входы политики и выходы настоящего аудита; статусы, доказательства, риск и версия
набора правил.

[Исходный файл](../src/cloud_audit/models/security.py)

Зависимости: `dataclasses`, `cloud_audit.models.resources`.

Поле/константа `FINDING_STATUSES`:

```python
FINDING_STATUSES = frozenset({'confirmed_violation', 'potential_risk', 'passed', 'insufficient_data', 'not_applicable'})
```

Поле/константа `CURRENT_RULESET_VERSION`:

```python
CURRENT_RULESET_VERSION = '1'
```

### Класс `RuleException`

[Определение](../src/cloud_audit/models/security.py#L16)

Принятое исключение для точной пары ресурс/правило с причиной и необязательным сроком.

Поле/константа `RuleException.resource_id`:

```python
resource_id: str
```

Поле/константа `RuleException.rule_id`:

```python
rule_id: str
```

Поле/константа `RuleException.reason`:

```python
reason: str
```

Поле/константа `RuleException.expires_at`:

```python
expires_at: str | None = None
```

### Класс `PermissionRequirement`

[Определение](../src/cloud_audit/models/security.py#L25)

Заданные необходимые операции одного субъекта, с которыми сравниваются явные гранты.

Поле/константа `PermissionRequirement.subject`:

```python
subject: str
```

Поле/константа `PermissionRequirement.operations`:

```python
operations: tuple[str, ...]
```

### Класс `AuditPolicy`

[Определение](../src/cloud_audit/models/security.py#L32)

Контекст оценки: чувствительность, обязательность контролей, доверенные субъекты, baseline и
исключения.

Поле/константа `AuditPolicy.data_sensitivity`:

```python
data_sensitivity: str = 'unknown'
```

Поле/константа `AuditPolicy.required_controls`:

```python
required_controls: tuple[str, ...] = ('versioning',)
```

Поле/константа `AuditPolicy.allowed_external_accounts`:

```python
allowed_external_accounts: tuple[str, ...] = ()
```

Поле/константа `AuditPolicy.required_permissions`:

```python
required_permissions: tuple[PermissionRequirement, ...] = ()
```

Поле/константа `AuditPolicy.exceptions`:

```python
exceptions: tuple[RuleException, ...] = ()
```

Поле/константа `AuditPolicy.trusted_project_ids`:

```python
trusted_project_ids: tuple[str, ...] = ()
```

### Класс `Evidence`

[Определение](../src/cloud_audit/models/security.py#L46)

Нормализованный факт: поле, источник, статус наблюдения и строковое значение, без содержимого
файлов.

Поле/константа `Evidence.field`:

```python
field: str
```

Поле/константа `Evidence.source`:

```python
source: str
```

Поле/константа `Evidence.observation_status`:

```python
observation_status: str
```

Поле/константа `Evidence.value`:

```python
value: str | None
```

### Класс `RiskAssessment`

[Определение](../src/cloud_audit/models/security.py#L58)

Объяснимая порядковая оценка: уровень, балл, вероятность/ущерб как категории и затронутые операции.

Поле/константа `RiskAssessment.level`:

```python
level: str
```

Поле/константа `RiskAssessment.score`:

```python
score: int | None
```

Поле/константа `RiskAssessment.likelihood`:

```python
likelihood: int | None
```

Поле/константа `RiskAssessment.impact`:

```python
impact: int | None
```

Поле/константа `RiskAssessment.rationale`:

```python
rationale: str
```

Поле/константа `RiskAssessment.affected_operations`:

```python
affected_operations: tuple[str, ...] = ()
```

Поле/константа `RiskAssessment.model_version`:

```python
model_version: int = 1
```

### Класс `Finding`

[Определение](../src/cloud_audit/models/security.py#L70)

Результат одного правила с доказательствами, риском, рекомендацией, подтверждением и ограничениями.

Поле/константа `Finding.rule_id`:

```python
rule_id: str
```

Поле/константа `Finding.status`:

```python
status: str
```

Поле/константа `Finding.explanation`:

```python
explanation: str
```

Поле/константа `Finding.evidence`:

```python
evidence: tuple[Evidence, ...]
```

Поле/константа `Finding.risk`:

```python
risk: RiskAssessment
```

Поле/константа `Finding.recommendation`:

```python
recommendation: str
```

Поле/константа `Finding.verification`:

```python
verification: str
```

Поле/константа `Finding.exception_reason`:

```python
exception_reason: str | None = None
```

Поле/константа `Finding.limitations`:

```python
limitations: tuple[str, ...] = ()
```

### Класс `SecurityReport`

[Определение](../src/cloud_audit/models/security.py#L84)

Самодостаточный настоящий отчёт со временем, снимком, охватом, политикой, результатами и provenance.

Поле/константа `SecurityReport.id`:

```python
id: str
```

Поле/константа `SecurityReport.schema_version`:

```python
schema_version: int
```

Поле/константа `SecurityReport.mode`:

```python
mode: str
```

Поле/константа `SecurityReport.resource`:

```python
resource: Resource
```

Поле/константа `SecurityReport.snapshot_id`:

```python
snapshot_id: str
```

Поле/константа `SecurityReport.snapshot_collected_at`:

```python
snapshot_collected_at: str
```

Поле/константа `SecurityReport.evaluated_at`:

```python
evaluated_at: str
```

Поле/константа `SecurityReport.scope`:

```python
scope: str
```

Поле/константа `SecurityReport.limitations`:

```python
limitations: tuple[str, ...]
```

Поле/константа `SecurityReport.collection_status`:

```python
collection_status: str
```

Поле/константа `SecurityReport.evaluation_status`:

```python
evaluation_status: str
```

Поле/константа `SecurityReport.policy`:

```python
policy: AuditPolicy
```

Поле/константа `SecurityReport.results`:

```python
results: tuple[Finding, ...]
```

Поле/константа `SecurityReport.object_keys`:

```python
object_keys: tuple[str, ...] = ()
```

Поле/константа `SecurityReport.ruleset_version`:

```python
ruleset_version: str | None = None
```

Поле/константа `SecurityReport.resource_namespace`:

```python
resource_namespace: str | None = None
```

## `src/cloud_audit/models/settings.py`

Настройки окружения и S3. Ключи исключены из repr; сериализация настроек в отчёты не предусмотрена.

[Исходный файл](../src/cloud_audit/models/settings.py)

Зависимости: `dataclasses`, `pathlib`.

### Класс `Settings`

[Определение](../src/cloud_audit/models/settings.py#L7)

Параметры среды, уровня журнала и выделенного корня состояния.

Поле/константа `Settings.environment`:

```python
environment: str
```

Поле/константа `Settings.log_level`:

```python
log_level: str
```

Поле/константа `Settings.state_dir`:

```python
state_dir: Path
```

### Класс `S3Settings`

[Определение](../src/cloud_audit/models/settings.py#L15)

HTTPS endpoint, регион подписи и ключи с repr=False; не передаётся модели ИИ.

Поле/константа `S3Settings.endpoint_url`:

```python
endpoint_url: str
```

Поле/константа `S3Settings.region`:

```python
region: str
```

Поле/константа `S3Settings.access_key`:

```python
access_key: str = field(repr=False)
```

Поле/константа `S3Settings.secret_key`:

```python
secret_key: str = field(repr=False)
```

## `src/cloud_audit/models/snapshot.py`

Факты конфигурации до оценки безопасности: выбранный охват, наблюдения, параметры проб и полнота сбора.

[Исходный файл](../src/cloud_audit/models/snapshot.py)

Зависимости: `dataclasses`, `cloud_audit.models.resources`.

Поле/константа `CONFIGURATION_FIELDS`:

```python
CONFIGURATION_FIELDS = frozenset({'bucket_acl', 'bucket_policy', 'public_access_block', 'ownership_controls', 'versioning', 'logging', 'encryption', 'object_lock'})
```

Поле/константа `OBSERVATION_STATUSES`:

```python
OBSERVATION_STATUSES = frozenset({'available', 'absent', 'access_denied', 'unsupported', 'error', 'not_found'})
```

Поле/константа `LIMITATIONS`:

```python
LIMITATIONS = ('object_acl_not_collected', 'object_contents_not_collected', 'account_controls_not_collected', 'security_not_assessed', 'sequential_requests_not_atomic')
```

### Класс `CollectionOptions`

[Определение](../src/cloud_audit/models/snapshot.py#L18)

Охват до 20 уникальных объектов и явные разрешения на unsigned и мутационные пробы.

Поле/константа `CollectionOptions.object_keys`:

```python
object_keys: tuple[str, ...] = ()
```

Поле/константа `CollectionOptions.probe_anonymous`:

```python
probe_anonymous: bool = False
```

Поле/константа `CollectionOptions.allow_write_probes`:

```python
allow_write_probes: bool = False
```

### Функция/метод `CollectionOptions.__post_init__`

[Определение](../src/cloud_audit/models/snapshot.py#L24)

Проверяет максимум 20 уникальных непустых ключей до 1024 байт и зависимость write-проб от
probe_anonymous.

```python
def __post_init__(self)
```

### Функция/метод `collection_limitations`

[Определение](../src/cloud_audit/models/snapshot.py#L36)

Формирует ограничения выбранного охвата, отсутствия содержимого/контролей аккаунта и
неатомарности сбора.

```python
def collection_limitations(keys: tuple[str, ...])
```

### Функция/метод `collection_complete`

[Определение](../src/cloud_audit/models/snapshot.py#L46)

Возвращает полноту только при available/absent и определённых результатах проб без ошибки уборки.

```python
def collection_complete(observations)
```

### Класс `ConfigurationObservation`

[Определение](../src/cloud_audit/models/snapshot.py#L55)

Один факт, полученный из API: источник, статус, нормализованные данные или безопасная причина
недоступности.

Поле/константа `ConfigurationObservation.name`:

```python
name: str
```

Поле/константа `ConfigurationObservation.source`:

```python
source: str
```

Поле/константа `ConfigurationObservation.status`:

```python
status: str
```

Поле/константа `ConfigurationObservation.data`:

```python
data: dict | None
```

Поле/константа `ConfigurationObservation.reason`:

```python
reason: str | None = None
```

### Класс `ConfigurationSnapshot`

[Определение](../src/cloud_audit/models/snapshot.py#L68)

Сохранённый вход аудита: ресурс, начало сбора, наблюдения, охват, namespace и ограничения.

Поле/константа `ConfigurationSnapshot.id`:

```python
id: str
```

Поле/константа `ConfigurationSnapshot.schema_version`:

```python
schema_version: int
```

Поле/константа `ConfigurationSnapshot.provider`:

```python
provider: str
```

Поле/константа `ConfigurationSnapshot.resource`:

```python
resource: Resource
```

Поле/константа `ConfigurationSnapshot.collected_at`:

```python
collected_at: str
```

Поле/константа `ConfigurationSnapshot.scope`:

```python
scope: str
```

Поле/константа `ConfigurationSnapshot.limitations`:

```python
limitations: tuple[str, ...]
```

Поле/константа `ConfigurationSnapshot.collection_status`:

```python
collection_status: str
```

Поле/константа `ConfigurationSnapshot.observations`:

```python
observations: tuple[ConfigurationObservation, ...]
```

Поле/константа `ConfigurationSnapshot.object_keys`:

```python
object_keys: tuple[str, ...] = ()
```

Поле/константа `ConfigurationSnapshot.resource_namespace`:

```python
resource_namespace: str | None = None
```

## `src/cloud_audit/providers/__init__.py`

Облачные и демонстрационные адаптеры, сетевые запросы и нормализация.

[Исходный файл](../src/cloud_audit/providers/__init__.py)

## `src/cloud_audit/providers/anonymous.py`

Отдельный unsigned-клиент для ограниченных проб; запись/удаление разрешены только на новых
искусственных ключах с уборкой.

[Исходный файл](../src/cloud_audit/providers/anonymous.py)

Зависимости: `datetime`, `logging`, `uuid`, `boto3`, `botocore`, `botocore.config`, `botocore.exceptions`, `botocore.parsers`, `cloud_audit.models.snapshot`.

### Класс `AnonymousProber`

[Определение](../src/cloud_audit/providers/anonymous.py#L18)

Выполняет независимые анонимные запросы и изолированные мутационные пробы с очисткой.

### Функция/метод `AnonymousProber.__init__`

[Определение](../src/cloud_audit/providers/anonymous.py#L20)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, anonymous_client, fixture_client=None)
```

### Функция/метод `AnonymousProber.from_settings`

[Определение](../src/cloud_audit/providers/anonymous.py#L29)

Создаёт клиента с signature_version=UNSIGNED, пустыми ключами и одной попыткой; ключи
окружения не используются.

```python
def from_settings(cls, settings, fixture_client=None)
```

### Функция/метод `AnonymousProber._probe`

[Определение](../src/cloud_audit/providers/anonymous.py#L43)

Выполняет запрос, ограниченно читает и закрывает Body; сохраняет только outcome, HTTP-код,
время и ключ.

```python
def _probe(self, name, source, operation, key=None)
```

### Функция/метод `AnonymousProber.read_only`

[Определение](../src/cloud_audit/providers/anonymous.py#L72)

Проверяет ListObjectsV2 MaxKeys=1 и GET Range bytes=0-0 для каждого выбранного объекта.

```python
def read_only(self, bucket: str, keys: tuple[str, ...])
```

### Функция/метод `AnonymousProber.mutations`

[Определение](../src/cloud_audit/providers/anonymous.py#L81)

Проверяет только новые UUID-ключи, предварительно перечисляет версии, выполняет put/delete и
удаляет точные версии/маркеры; отмечает cleanup_failed.

```python
def mutations(self, bucket: str, *, enabled: bool=False)
```

## `src/cloud_audit/providers/collection.py`

Читает восемь настроек бакета и ACL выбранных объектов; нормализует ответы SDK и различает причины
недоступности.

[Исходный файл](../src/cloud_audit/providers/collection.py)

Зависимости: `json`, `botocore.exceptions`, `botocore.parsers`, `cloud_audit.errors`, `cloud_audit.models.resources`, `cloud_audit.models.snapshot`.

### Функция/метод `require_mapping`

[Определение](../src/cloud_audit/providers/collection.py#L15)

Требует dict в ответе SDK; иначе ValueError преобразуется коллектором в invalid_response.

```python
def require_mapping(value)
```

### Функция/метод `acl`

[Определение](../src/cloud_audit/providers/collection.py#L22)

Нормализует владельца и гранты ACL: тип субъекта, идентификатор и разрешение; SDK-метаданные
исключает.

```python
def acl(response)
```

### Функция/метод `policy`

[Определение](../src/cloud_audit/providers/collection.py#L46)

Разбирает JSON Policy и сохраняет исходный документ, включая неизвестные условия, без интерпретации.

```python
def policy(response)
```

### Функция/метод `public_access`

[Определение](../src/cloud_audit/providers/collection.py#L60)

Проверяет четыре булевых поля Block Public Access и преобразует их имена в snake_case.

```python
def public_access(response)
```

### Функция/метод `ownership`

[Определение](../src/cloud_audit/providers/collection.py#L70)

Требует одно правило Ownership Controls и распознанный ObjectOwnership.

```python
def ownership(response)
```

### Функция/метод `versioning`

[Определение](../src/cloud_audit/providers/collection.py#L81)

Нормализует Status и MFADelete; отсутствие Status означает Disabled, отсутствие MFADelete
остаётся None.

```python
def versioning(response)
```

### Функция/метод `logging_configuration`

[Определение](../src/cloud_audit/providers/collection.py#L93)

Пустой ответ означает отсутствие настроенного журнала; иначе проверяет target_bucket/target_prefix.

```python
def logging_configuration(response)
```

### Функция/метод `encryption`

[Определение](../src/cloud_audit/providers/collection.py#L103)

Проверяет список алгоритмов шифрования и необязательные KMS ID/BucketKeyEnabled; не утверждает
реальное шифрование объектов.

```python
def encryption(response)
```

### Функция/метод `object_lock`

[Определение](../src/cloud_audit/providers/collection.py#L130)

Проверяет включение Object Lock и, если указан, положительный срок Days либо Years в допустимом
режиме.

```python
def object_lock(response)
```

Поле/константа `COLLECTION_SPECS`:

```python
COLLECTION_SPECS = (('bucket_acl', 'get_bucket_acl', acl, frozenset()), ('bucket_policy', 'get_bucket_policy', policy, {'NoSuchBucketPolicy'}), ('public_access_block', 'get_public_access_block', public_access, {'NoSuchPublicAccessBlockConfiguration'}), ('ownership_controls', 'get_bucket_ownership_controls', ownership, {'OwnershipControlsNotFoundError'}), ('versioning', 'get_bucket_versioning', versioning, frozenset()), ('logging', 'get_bucket_logging', logging_configuration, frozenset()), ('encryption', 'get_bucket_encryption', encryption, {'ServerSideEncryptionConfigurationNotFoundError'}), ('object_lock', 'get_object_lock_configuration', object_lock, {'ObjectLockConfigurationNotFoundError'}))
```

### Класс `S3ConfigurationCollector`

[Определение](../src/cloud_audit/providers/collection.py#L165)

Читает только Get-настройки и нормализует их; отсутствие настройки и ошибка API различаются.

Поле/константа `S3ConfigurationCollector.mode`:

```python
mode = 'vk'
```

Поле/константа `S3ConfigurationCollector.namespace`:

```python
namespace = None
```

### Функция/метод `S3ConfigurationCollector.__init__`

[Определение](../src/cloud_audit/providers/collection.py#L169)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, client)
```

### Функция/метод `S3ConfigurationCollector.collect`

[Определение](../src/cloud_audit/providers/collection.py#L176)

Последовательно читает COLLECTION_SPECS и ACL только явно выбранных ключей; содержимое
файлов не читает.

```python
def collect(self, resource: Resource, options: CollectionOptions | None=None) -> tuple[ConfigurationObservation, ...]
```

### Функция/метод `S3ConfigurationCollector._read`

[Определение](../src/cloud_audit/providers/collection.py#L187)

Вызывает один Get, нормализует ответ; различает absent/denied/unsupported/not_found/error,
прерывает сбор при ошибке ключей/бакета.

```python
def _read(self, bucket, name, method, normalize, absence_codes, key=None)
```

## `src/cloud_audit/providers/demo.py`

Фиксированный демонстрационный профиль без сети; результаты всегда simulated и не являются оценкой
безопасности.

[Исходный файл](../src/cloud_audit/providers/demo.py)

Зависимости: `cloud_audit.errors`, `cloud_audit.models.resources`.

### Класс `DemoProvider`

[Определение](../src/cloud_audit/providers/demo.py#L9)

Fixed fixtures, not a security rule engine or a cloud connection.

Поле/константа `DemoProvider.mode`:

```python
mode = 'demo'
```

Поле/константа `DemoProvider.connection_message`:

```python
connection_message = 'Simulated connection; no cloud contacted'
```

### Функция/метод `DemoProvider.connect`

[Определение](../src/cloud_audit/providers/demo.py#L14)

Демонстрационная операция без сетевых запросов и изменения состояния.

```python
def connect(self) -> None
```

### Функция/метод `DemoProvider.resources`

[Определение](../src/cloud_audit/providers/demo.py#L18)

Возвращает два фиксированных ресурса demo-public/demo-private.

```python
def resources(self) -> tuple[Resource, ...]
```

### Функция/метод `DemoProvider.preview`

[Определение](../src/cloud_audit/providers/demo.py#L23)

Разрешает только demo-public-read и возвращает simulated с описанием фикстуры; неизвестные
ID отклоняет.

```python
def preview(self, resource: Resource, rules: tuple[str, ...]) -> tuple[RuleResult, ...]
```

## `src/cloud_audit/providers/discovery.py`

Постраничный список объектов с пределами объёма и запросов; ошибка не становится пустым успехом.

[Исходный файл](../src/cloud_audit/providers/discovery.py)

Зависимости: `datetime`, `botocore.exceptions`, `botocore.parsers`, `cloud_audit.models.scanning`.

### Класс `ObjectEnumerator`

[Определение](../src/cloud_audit/providers/discovery.py#L9)

Использует переданный signed/unsigned клиент; возвращает охват и факт самого List-запроса.

### Функция/метод `ObjectEnumerator.__init__`

[Определение](../src/cloud_audit/providers/discovery.py#L11)

Фиксирует клиент и вид авторизации для доказательств.

```python
def __init__(self, client, source)
```

### Функция/метод `ObjectEnumerator.list`

[Определение](../src/cloud_audit/providers/discovery.py#L15)

Читает до limit уникальных ключей и максимум 20 страниц, обнаруживая неверные токены/ответы.

```python
def list(self, bucket, limit)
```

## `src/cloud_audit/providers/external.py`

Внешний этап: unsigned List/Get и отдельно разрешённые искусственные Write/Delete.

[Исходный файл](../src/cloud_audit/providers/external.py)

Зависимости: `dataclasses`, `cloud_audit.models.scanning`, `cloud_audit.providers.anonymous`, `cloud_audit.providers.discovery`, `cloud_audit.providers.mutations`, `datetime`.

### Класс `ExternalInspector`

[Определение](../src/cloud_audit/providers/external.py#L10)

Не требует ключей; переданный signed-клиент применяется только для подготовки/уборки мутаций.

### Функция/метод `ExternalInspector.__init__`

[Определение](../src/cloud_audit/providers/external.py#L12)

Сохраняет разделённые клиенты и идентичность endpoint.

```python
def __init__(self, anonymous, namespace, signed=None)
```

### Функция/метод `ExternalInspector.from_settings`

[Определение](../src/cloud_audit/providers/external.py#L18)

Использует существующую фабрику UNSIGNED с пустыми credentials, даже если ключи заданы в окружении.

```python
def from_settings(cls, settings, signed=None)
```

### Функция/метод `ExternalInspector.inspect`

[Определение](../src/cloud_audit/providers/external.py#L23)

Сначала List/Get, затем только явно разрешённые мутации выбранного бакета.

```python
def inspect(self, target, limit)
```

### Функция/метод `ExternalInspector.read_objects`

[Определение](../src/cloud_audit/providers/external.py#L37)

GET Range bytes=0-0 каждого выбранного ключа, без повторного List или мутаций.

```python
def read_objects(self, bucket, keys)
```

## `src/cloud_audit/providers/mutations.py`

Изолированные unsigned PUT/DELETE с отдельными signed-подготовкой, подтверждением и уборкой.

[Исходный файл](../src/cloud_audit/providers/mutations.py)

Зависимости: `dataclasses`, `datetime`, `uuid`, `botocore.exceptions`, `botocore.parsers`, `cloud_audit.models.scanning`.

Поле/константа `ERRORS`:

```python
ERRORS = (BotoCoreError, ClientError, ResponseParserError, OSError, ValueError, TypeError, KeyError, AttributeError)
```

### Класс `MutationProber`

[Определение](../src/cloud_audit/providers/mutations.py#L13)

Работает только со своими случайными ключами; неподтверждённый эффект не становится allowed.

### Функция/метод `MutationProber.__init__`

[Определение](../src/cloud_audit/providers/mutations.py#L15)

Разделяет клиента проверочных запросов и клиента подготовки/уборки.

```python
def __init__(self, anonymous, signed=None)
```

### Функция/метод `MutationProber.run`

[Определение](../src/cloud_audit/providers/mutations.py#L20)

Проверяет две независимые цели; без ключей требует согласия на возможные неудалённые файлы.

```python
def run(self, bucket, *, allow_residue=False)
```

### Функция/метод `MutationProber._ready`

[Определение](../src/cloud_audit/providers/mutations.py#L29)

Мутации с ключами требуют известного состояния версионирования и подтверждённого отсутствия Object Lock.

```python
def _ready(self, bucket)
```

### Функция/метод `MutationProber._result`

[Определение](../src/cloud_audit/providers/mutations.py#L46)

Создаёт приватное по составу доказательство без исходных сообщений SDK.

```python
def _result(self, operation, key, outcome, code=None, **kwargs)
```

### Функция/метод `MutationProber._request`

[Определение](../src/cloud_audit/providers/mutations.py#L50)

Выполняет только проверочный unsigned-запрос и классифицирует HTTP-ответ; возвращает также метаданные для уборки.

```python
def _request(self, operation, key, call)
```

### Функция/метод `MutationProber._one`

[Определение](../src/cloud_audit/providers/mutations.py#L65)

Проверяет отсутствие старых версий, готовит собственную цель и подтверждает удаление до уборки.

```python
def _one(self, bucket, key, operation)
```

### Функция/метод `MutationProber._present`

[Определение](../src/cloud_audit/providers/mutations.py#L107)

Возвращает True при HEAD 2xx, False только при точном 404 объекта, иначе неизвестность.

```python
def _present(self, client, bucket, key)
```

### Функция/метод `MutationProber._cleanup`

[Определение](../src/cloud_audit/providers/mutations.py#L118)

Удаляет только версии с меткой нашей пробы и известные маркеры; неизвестный остаток явно сохраняется в отчёте.

```python
def _cleanup(self, bucket, key, token, marker_ids, created, attempted)
```

## `src/cloud_audit/providers/s3.py`

Подписанный S3-адаптер: подключение, список бакетов, сбор настроек и включаемые явно анонимные пробы.

[Исходный файл](../src/cloud_audit/providers/s3.py)

Зависимости: `logging`, `boto3`, `botocore.config`, `botocore.exceptions`, `botocore.parsers`, `cloud_audit.errors`, `cloud_audit.models.resources`, `cloud_audit.models.snapshot`, `cloud_audit.models.settings`.

### Класс `S3Provider`

[Определение](../src/cloud_audit/providers/s3.py#L15)

Облачный профиль vk с подписанным клиентом, namespace и отдельным адаптером unsigned-проб.

Поле/константа `S3Provider.mode`:

```python
mode = 'vk'
```

Поле/константа `S3Provider.connection_message`:

```python
connection_message = 'Authenticated bucket listing succeeded; security not assessed'
```

### Функция/метод `S3Provider.__init__`

[Определение](../src/cloud_audit/providers/s3.py#L20)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, client, anonymous_prober=None, namespace=None)
```

### Функция/метод `S3Provider.from_settings`

[Определение](../src/cloud_audit/providers/s3.py#L30)

Создаёт подписанный path-style boto3-клиент с тайм-аутами 5/10 с, тремя попытками и
отдельный unsigned-клиент; подавляет SDK DEBUG.

```python
def from_settings(cls, settings: S3Settings)
```

### Функция/метод `S3Provider.connect`

[Определение](../src/cloud_audit/providers/s3.py#L47)

Проверяет авторизованное перечисление бакетов через resources; это не оценка их безопасности.

```python
def connect(self) -> None
```

### Функция/метод `S3Provider.resources`

[Определение](../src/cloud_audit/providers/s3.py#L51)

Обходит страницы ListBuckets, удаляет дубликаты, обнаруживает зацикливание; ошибки SDK
преобразует в безопасный AuditError.

```python
def resources(self) -> tuple[Resource, ...]
```

### Функция/метод `S3Provider.collect`

[Определение](../src/cloud_audit/providers/s3.py#L95)

Собирает настройки и при явных флагах пробы; мутации требуют подтверждённого отсутствия
Object Lock.

```python
def collect(self, resource: Resource, options: CollectionOptions | None=None) -> tuple[ConfigurationObservation, ...]
```

### Функция/метод `S3Provider.discover_objects`

[Определение](../src/cloud_audit/providers/s3.py#L114)

Перечисляет ограниченные ключи подписанным клиентом; не читает содержимое объектов.

```python
def discover_objects(self, bucket, limit)
```

## `src/cloud_audit/reports/__init__.py`

Представления, форматирование и экспорт результатов.

[Исходный файл](../src/cloud_audit/reports/__init__.py)

## `src/cloud_audit/reports/formatting.py`

Создаёт фильтрованные представления и Markdown; экранирует внешние строки и экспортирует в новый
приватный файл.

[Исходный файл](../src/cloud_audit/reports/formatting.py)

Зависимости: `dataclasses`, `html`, `json`, `os`, `pathlib`, `re`.

### Функция/метод `report_view`

[Определение](../src/cloud_audit/reports/formatting.py#L13)

Создаёт отдельное фильтрованное представление по rule/severity/status; сохраняет общий статус и
число результатов полного отчёта.

```python
def report_view(report, *, rule_id=None, severity=None, status=None)
```

### Функция/метод `safe`

[Определение](../src/cloud_audit/reports/formatting.py#L32)

Экранирует HTML и Markdown в одной строке внешних данных, чтобы они не меняли структуру отчёта.

```python
def safe(value)
```

### Функция/метод `code`

[Определение](../src/cloud_audit/reports/formatting.py#L38)

Форматирует данные JSON и выбирает ограждение длиннее вложенных backtick-последовательностей.

```python
def code(value)
```

### Функция/метод `render_markdown`

[Определение](../src/cloud_audit/reports/formatting.py#L46)

Формирует самостоятельный Markdown отчёта, истории или сравнения с контекстом, доказательствами
и ограничениями.

```python
def render_markdown(data)
```

### Функция/метод `write_document`

[Определение](../src/cloud_audit/reports/formatting.py#L101)

Создаёт новый файл 0600 через O_EXCL, записывает/синхронизирует текст; удаляет незавершённый
файл при ошибке.

```python
def write_document(path: Path, content: str) -> None
```

## `src/cloud_audit/reports/scanning.py`

Читаемая общая сводка ступенчатого запуска и полные доказательства каждого бакета.

[Исходный файл](../src/cloud_audit/reports/scanning.py)

### Функция/метод `render_scan`

[Определение](../src/cloud_audit/reports/scanning.py#L4)

Разделяет статусы операций и внутреннего анализа; выводит ограничения и остаточные цели.

```python
def render_scan(data, safe, code)
```

## `src/cloud_audit/rules/__init__.py`

Алгоритмы сканирования, реестр и оценка риска без обращения к облаку.

[Исходный файл](../src/cloud_audit/rules/__init__.py)

## `src/cloud_audit/rules/access_grants.py`

Строит инвентарь явных разрешений и запретов для выбранных ресурсов; не подменяет полный IAM и
действующие сеансы доступа.

[Исходный файл](../src/cloud_audit/rules/access_grants.py)

Зависимости: `dataclasses`, `json`, `re`, `cloud_audit.rules.public_access`, `cloud_audit.models.security`.

Поле/константа `ACTION_OPERATIONS`:

```python
ACTION_OPERATIONS = {'s3:GetObject': ('read', 'object'), 's3:ListBucket': ('list', 'bucket'), 's3:PutObject': ('write', 'object'), 's3:DeleteObject': ('delete', 'object'), 's3:GetBucketAcl': ('read_acl', 'bucket'), 's3:GetObjectAcl': ('read_acl', 'object'), 's3:PutBucketAcl': ('write_acl', 'bucket'), 's3:PutObjectAcl': ('write_acl', 'object'), 's3:GetBucketPolicy': ('read_policy', 'bucket')}
```

### Функция/метод `project_id`

[Определение](../src/cloud_audit/rules/access_grants.py#L23)

Извлекает проект из поддерживаемого IAM ARN пользователя/root; при другой форме возвращает None.

```python
def project_id(subject: str) -> str | None
```

### Функция/метод `subject_covers`

[Определение](../src/cloud_audit/rules/access_grants.py#L29)

Проверяет точный субъект, группу AuthenticatedUsers или покрытие пользователя проектным грантом.

```python
def subject_covers(grant: str, subject: str) -> bool
```

### Класс `ExplicitGrant`

[Определение](../src/cloud_audit/rules/access_grants.py#L37)

Явная операция субъекта над конкретным ARN с указанием источника.

Поле/константа `ExplicitGrant.subject`:

```python
subject: str
```

Поле/константа `ExplicitGrant.operation`:

```python
operation: str
```

Поле/константа `ExplicitGrant.resource`:

```python
resource: str
```

Поле/константа `ExplicitGrant.source`:

```python
source: str
```

### Класс `GrantInventory`

[Определение](../src/cloud_audit/rules/access_grants.py#L46)

Разрешения, запреты, доказательства, неизвестности и владелец в выбранном охвате.

Поле/константа `GrantInventory.grants`:

```python
grants: tuple[ExplicitGrant, ...]
```

Поле/константа `GrantInventory.denies`:

```python
denies: tuple[ExplicitGrant, ...]
```

Поле/константа `GrantInventory.evidence`:

```python
evidence: tuple[Evidence, ...]
```

Поле/константа `GrantInventory.unknown`:

```python
unknown: tuple[str, ...]
```

Поле/константа `GrantInventory.owner_id`:

```python
owner_id: str | None
```

### Функция/метод `GrantInventory.denied`

[Определение](../src/cloud_audit/rules/access_grants.py#L54)

Проверяет, перекрывает ли явный Deny операцию и ресурс гранта для указанного субъекта.

```python
def denied(self, grant: ExplicitGrant, subject: str | None=None) -> bool
```

### Функция/метод `GrantInventory.for_subject`

[Определение](../src/cloud_audit/rules/access_grants.py#L59)

Возвращает явные разрешения, покрывающие субъекта, за вычетом подходящих явных запретов.

```python
def for_subject(self, subject: str)
```

### Функция/метод `inventory`

[Определение](../src/cloud_audit/rules/access_grants.py#L65)

Нормализует явные ACL/политики в операции по выбранным целям; учитывает ownership, запреты и
неполноту анализа.

```python
def inventory(snapshot) -> GrantInventory
```

## `src/cloud_audit/rules/engine.py`

Выполняет зарегистрированные правила над снимком: выбор, применимость, обязательные данные и
документированные исключения.

[Исходный файл](../src/cloud_audit/rules/engine.py)

Зависимости: `dataclasses`, `datetime`, `cloud_audit.errors`, `cloud_audit.rules.risk`, `cloud_audit.interfaces`, `cloud_audit.models.security`, `cloud_audit.models.snapshot`.

### Класс `RuleEngine`

[Определение](../src/cloud_audit/rules/engine.py#L15)

Универсальный исполнитель правил, не зависящий от облачного SDK и формата хранения.

### Функция/метод `RuleEngine.__init__`

[Определение](../src/cloud_audit/rules/engine.py#L17)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, rules: tuple[SecurityRule, ...])
```

### Функция/метод `RuleEngine.select`

[Определение](../src/cloud_audit/rules/engine.py#L26)

Выбирает все или уникальные запрошенные ID в порядке запроса; неизвестные ID и пустой реестр
отклоняет AuditError.

```python
def select(self, selected: tuple[str, ...]) -> tuple[SecurityRule, ...]
```

### Функция/метод `RuleEngine.evaluate`

[Определение](../src/cloud_audit/rules/engine.py#L36)

Для каждого правила проверяет применимость/данные, выполняет алгоритм и добавляет
действующее исключение, не скрывая находку.

```python
def evaluate(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy, selected: tuple[str, ...]=()) -> tuple[Finding, ...]
```

## `src/cloud_audit/rules/external.py`

Оценка только наблюдавшихся unsigned-операций, без предположений о полной конфигурации.

[Исходный файл](../src/cloud_audit/rules/external.py)

Зависимости: `dataclasses`, `json`, `cloud_audit.models.security`, `cloud_audit.rules.risk`.

### Функция/метод `external_findings`

[Определение](../src/cloud_audit/rules/external.py#L9)

Группирует пробы четырёх операций; отказ относится только к проверенным целям, пропуск не даёт passed.

```python
def external_findings(probes, policy)
```

## `src/cloud_audit/rules/governance.py`

Правила внешних субъектов, превышения заданной модели необходимых прав и отключения ACL.

[Исходный файл](../src/cloud_audit/rules/governance.py)

Зависимости: `cloud_audit.rules.access_grants`, `cloud_audit.rules.risk`, `cloud_audit.models.security`.

Поле/константа `BASE_LIMITS`:

```python
BASE_LIMITS = ('only_explicit_grants_in_selected_scope', 'implicit_internal_permissions_not_evaluated', 'conditions_and_unmapped_actions_not_evaluated', 'grants_are_not_runtime_access_confirmation')
```

### Функция/метод `result`

[Определение](../src/cloud_audit/rules/governance.py#L11)

Собирает Finding правила управления доступом, общие ограничения, риск и уникальные операции;
обеспечивает минимальное доказательство.

```python
def result(rule, snapshot, policy, status, explanation, evidence, operations=(), limitations=())
```

### Класс `GovernanceRule`

[Определение](../src/cloud_audit/rules/governance.py#L24)

Общая проверка применимости правил управления доступом к поддерживаемому охвату.

Поле/константа `GovernanceRule.required_data`:

```python
required_data = ()
```

### Функция/метод `GovernanceRule.applicable`

[Определение](../src/cloud_audit/rules/governance.py#L27)

Проверяет поддерживаемый scope снимка; при неприменимости движок формирует not_applicable
без выполнения алгоритма.

```python
def applicable(self, snapshot, policy)
```

### Класс `ExternalAccessRule`

[Определение](../src/cloud_audit/rules/governance.py#L35)

Выявляет явные гранты неутверждённым внешним субъектам, с учётом доверия и запретов.

Базовые классы: `GovernanceRule`.

Поле/константа `ExternalAccessRule.id`:

```python
id = 'unapproved-external-access'
```

Поле/константа `ExternalAccessRule.recommendation`:

```python
recommendation = 'In VK Cloud review the named principals in the bucket policy and the bucket/object ACLs. Remove unintended grants or document specific approved project/account identifiers; do not remove the owner or required application access without checking dependencies.'
```

Поле/константа `ExternalAccessRule.verification`:

```python
verification = 'Collect fresh settings, supply trusted_project_ids and allowed_external_accounts, and rerun this rule. Validate actual access separately with the affected subject.'
```

### Функция/метод `ExternalAccessRule.evaluate`

[Определение](../src/cloud_audit/rules/governance.py#L44)

Исключает анонимные/доверенные/разрешённые и запрещённые гранты; внешние явные права дают
potential_risk, недостающий контекст — insufficient_data.

```python
def evaluate(self, snapshot, policy)
```

### Класс `ExcessPermissionsRule`

[Определение](../src/cloud_audit/rules/governance.py#L76)

Сравнивает наблюдаемые явные операции с пользовательской baseline; не выводит её из текущих прав.

Базовые классы: `GovernanceRule`.

Поле/константа `ExcessPermissionsRule.id`:

```python
id = 'excess-explicit-permissions'
```

Поле/константа `ExcessPermissionsRule.recommendation`:

```python
recommendation = 'In VK Cloud narrow policy Action/Resource and ACL permissions to the required_permissions baseline for each subject. Bucket WRITE also grants deletion; FULL_CONTROL includes ACL changes. Confirm application requirements before removing access.'
```

Поле/константа `ExcessPermissionsRule.verification`:

```python
verification = 'Record required operations for each exact subject, collect fresh policy/ACL data and rerun. Check required application actions separately; this rule does not test missing necessary access.'
```

### Функция/метод `ExcessPermissionsRule.evaluate`

[Определение](../src/cloud_audit/rules/governance.py#L85)

Для заданных субъектов сравнивает явные операции с required_permissions; превышение даёт
risk, неполнота не позволяет заявить least privilege.

```python
def evaluate(self, snapshot, policy)
```

### Класс `AclDisabledRule`

[Определение](../src/cloud_audit/rules/governance.py#L116)

Проверяет BucketOwnerEnforced и учитывает обязательность отключения ACL в политике аудита.

Базовые классы: `GovernanceRule`.

Поле/константа `AclDisabledRule.id`:

```python
id = 'bucket-acl-disabled'
```

Поле/константа `AclDisabledRule.required_data`:

```python
required_data = ('ownership_controls',)
```

Поле/константа `AclDisabledRule.recommendation`:

```python
recommendation = 'In VK Cloud review applications that depend on ACLs, migrate required permissions to bucket policies, then disable ACLs (BucketOwnerEnforced). This reduces accidental ACL publication but does not prevent public access through policies.'
```

Поле/константа `AclDisabledRule.verification`:

```python
verification = 'Collect fresh Ownership Controls and confirm BucketOwnerEnforced; rerun anonymous access rules and application access checks after the migration.'
```

### Функция/метод `AclDisabledRule.evaluate`

[Определение](../src/cloud_audit/rules/governance.py#L126)

Сопоставляет Ownership Controls и required_controls: Enforced passed, Preferred/Writer risk
или нарушение baseline, неизвестное insufficient_data.

```python
def evaluate(self, snapshot, policy)
```

## `src/cloud_audit/rules/public_access.py`

Консервативно оценивает анонимные read/list/write/delete по выбранным целям, поддерживаемым
политикам, ACL и unsigned-пробам.

[Исходный файл](../src/cloud_audit/rules/public_access.py)

Зависимости: `dataclasses`, `json`, `re`, `cloud_audit.rules.risk`, `cloud_audit.models.security`, `cloud_audit.models.snapshot`.

Поле/константа `ALL_USERS`:

```python
ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers'
```

Поле/константа `ACTIONS`:

```python
ACTIONS = {'read': 's3:GetObject', 'list': 's3:ListBucket', 'write': 's3:PutObject', 'delete': 's3:DeleteObject'}
```

### Функция/метод `matches`

[Определение](../src/cloud_audit/rules/public_access.py#L19)

Сопоставляет IAM-маски * и ? через экранированное регулярное выражение; [] не трактуются как
shell-классы.

```python
def matches(pattern: str, value: str) -> bool
```

### Функция/метод `strings`

[Определение](../src/cloud_audit/rules/public_access.py#L28)

Приводит строку или непустой список строк политики к списку; некорректную форму отклоняет
ValueError.

```python
def strings(value)
```

### Класс `PolicyDecision`

[Определение](../src/cloud_audit/rules/public_access.py#L40)

Решение поддерживаемой части политики: отдельные признаки Allow, Deny и неизвестности.

Поле/константа `PolicyDecision.allow`:

```python
allow: bool = False
```

Поле/константа `PolicyDecision.deny`:

```python
deny: bool = False
```

Поле/константа `PolicyDecision.unknown`:

```python
unknown: bool = False
```

### Функция/метод `policy_decision`

[Определение](../src/cloud_audit/rules/public_access.py#L47)

Рассматривает подходящие Action/Resource/Principal; сохраняет неизвестность Condition/Not*,
различает Allow и безусловный Deny.

```python
def policy_decision(observation, action: str, resource: str) -> PolicyDecision
```

### Функция/метод `acl_allows`

[Определение](../src/cloud_audit/rules/public_access.py#L93)

Ищет нужные разрешения только у AllUsers; возвращает None, если ACL нельзя надёжно интерпретировать.

```python
def acl_allows(observation, permissions: set[str]) -> bool | None
```

### Класс `PublicAccessRule`

[Определение](../src/cloud_audit/rules/public_access.py#L107)

Параметризованная проверка одной анонимной операции; подтверждение запросом отделено от
предположения по настройкам.

Поле/константа `PublicAccessRule.required_data`:

```python
required_data = ()
```

Поле/константа `PublicAccessRule.recommendation`:

```python
recommendation = 'Remove unintended anonymous Allow statements and AllUsers ACL grants for this operation. Keep explicit approved exceptions documented; check bucket and object ACL separately.'
```

Поле/константа `PublicAccessRule.verification`:

```python
verification = 'Collect fresh configuration and repeat an unsigned request on the same artificial object or bucket listing. A 403 proves denial only for that request, not every object or client.'
```

### Функция/метод `PublicAccessRule.__init__`

[Определение](../src/cloud_audit/rules/public_access.py#L118)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, operation: str)
```

### Функция/метод `PublicAccessRule.applicable`

[Определение](../src/cloud_audit/rules/public_access.py#L128)

Проверяет поддерживаемый scope снимка; при неприменимости движок формирует not_applicable
без выполнения алгоритма.

```python
def applicable(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> bool
```

### Функция/метод `PublicAccessRule.evaluate`

[Определение](../src/cloud_audit/rules/public_access.py#L135)

Положительная unsigned-проба подтверждает доступ; иначе сопоставляет политики/ACL/запреты по
каждой цели; неполноту не превращает в passed.

```python
def evaluate(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> Finding
```

## `src/cloud_audit/rules/registry.py`

Собирает восемь встроенных правил в стабильном порядке; реестр передаётся движку через конструктор.

[Исходный файл](../src/cloud_audit/rules/registry.py)

Зависимости: `cloud_audit.rules.versioning`, `cloud_audit.rules.public_access`, `cloud_audit.rules.governance`.

### Функция/метод `default_rules`

[Определение](../src/cloud_audit/rules/registry.py#L7)

Возвращает восемь встроенных проверок в фиксированном порядке, без обращения к внешним системам.

```python
def default_rules()
```

## `src/cloud_audit/rules/risk.py`

Единая порядковая оценка опасности: учитывает чувствительность данных и подтверждение публичного
доступа, не вычисляет статистическую вероятность.

[Исходный файл](../src/cloud_audit/rules/risk.py)

Зависимости: `cloud_audit.models.security`.

### Класс `RiskModel`

[Определение](../src/cloud_audit/rules/risk.py#L8)

Ordinal, documented prioritization; not a measured incident probability.

### Функция/метод `RiskModel.assess`

[Определение](../src/cloud_audit/rules/risk.py#L10)

Для passed/n/a возвращает 0; для insufficient_data — unknown; иначе impact 1..3 × likelihood
2 либо 3 и текстовое обоснование.

```python
def assess(self, status: str, sensitivity: str, operations: tuple[str, ...]=(), exposure: str='unknown') -> RiskAssessment
```

## `src/cloud_audit/rules/versioning.py`

Проверяет состояние версионирования и сопоставляет его с обязательностью контроля восстановления.

[Исходный файл](../src/cloud_audit/rules/versioning.py)

Зависимости: `cloud_audit.rules.risk`, `cloud_audit.models.security`, `cloud_audit.models.snapshot`.

### Класс `VersioningRule`

[Определение](../src/cloud_audit/rules/versioning.py#L7)

Проверка включённого версионирования, не гарантия резервного копирования или отсутствия
публичного доступа.

Поле/константа `VersioningRule.id`:

```python
id = 'bucket-versioning-enabled'
```

Поле/константа `VersioningRule.required_data`:

```python
required_data = ('versioning',)
```

Поле/константа `VersioningRule.recommendation`:

```python
recommendation = 'In VK Cloud, open the training bucket settings and enable versioning if required by the recovery policy. Review retention and storage costs; existing lost versions cannot be recovered by enabling versioning later.'
```

Поле/константа `VersioningRule.verification`:

```python
verification = 'Collect a new snapshot and confirm GetBucketVersioning Status=Enabled; repeat this rule. Test recovery separately on artificial objects.'
```

### Функция/метод `VersioningRule.applicable`

[Определение](../src/cloud_audit/rules/versioning.py#L20)

Проверяет поддерживаемый scope снимка; при неприменимости движок формирует not_applicable
без выполнения алгоритма.

```python
def applicable(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> bool
```

### Функция/метод `VersioningRule.evaluate`

[Определение](../src/cloud_audit/rules/versioning.py#L27)

Enabled даёт passed; Disabled/Suspended — нарушение обязательного versioning либо
potential_risk; неизвестное значение — insufficient_data.

```python
def evaluate(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> Finding
```

## `src/cloud_audit/scan_cli.py`

Аргументы и сборка зависимостей ступенчатого scan, отдельно от прежних одиночных команд.

[Исходный файл](../src/cloud_audit/scan_cli.py)

Зависимости: `dataclasses`, `pathlib`, `cloud_audit.configuration.environment`, `cloud_audit.configuration.policy`, `cloud_audit.configuration.targets`, `cloud_audit.errors`, `cloud_audit.models.scanning`, `cloud_audit.providers.external`, `cloud_audit.providers.s3`, `cloud_audit.rules.engine`, `cloud_audit.rules.registry`, `cloud_audit.services.audit`, `cloud_audit.services.scanning`, `cloud_audit.services.snapshots`, `cloud_audit.storage.scans`.

### Функция/метод `add_scan_commands`

[Определение](../src/cloud_audit/scan_cli.py#L20)

Добавляет три взаимоисключающих источника целей и отдельное офлайн-чтение сводки.

```python
def add_scan_commands(commands)
```

### Функция/метод `execute_scan`

[Определение](../src/cloud_audit/scan_cli.py#L39)

Создаёт signed-клиента только при полной паре ключей; внешний клиент всегда UNSIGNED.

```python
def execute_scan(args, settings, reports, snapshots, configuration)
```

## `src/cloud_audit/services/__init__.py`

Сценарии работы приложения над внедряемыми интерфейсами.

[Исходный файл](../src/cloud_audit/services/__init__.py)

## `src/cloud_audit/services/audit.py`

Запускает движок, объединяет ограничения, формирует SecurityReport v3 и сохраняет его через
интерфейс репозитория.

[Исходный файл](../src/cloud_audit/services/audit.py)

Зависимости: `datetime`, `uuid`, `cloud_audit.interfaces`, `cloud_audit.rules.engine`, `cloud_audit.models.security`, `cloud_audit.models.snapshot`.

### Класс `SecurityAuditService`

[Определение](../src/cloud_audit/services/audit.py#L14)

Формирует и сохраняет настоящий отчёт на основании снимка и результатов движка.

### Функция/метод `SecurityAuditService.__init__`

[Определение](../src/cloud_audit/services/audit.py#L16)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, engine: RuleEngine, reports: SecurityReportRepository)
```

### Функция/метод `SecurityAuditService.audit`

[Определение](../src/cloud_audit/services/audit.py#L24)

Выполняет правила, объединяет ограничения/ошибки уборки, создаёт v3 с
UUID/временем/namespace/версией и сохраняет.

```python
def audit(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy, selected: tuple[str, ...]=()) -> SecurityReport
```

## `src/cloud_audit/services/comparison.py`

Сравнивает ресурс, контекст, охват и результаты; требует новых сопоставимых доказательств, чтобы
объявить устранение.

[Исходный файл](../src/cloud_audit/services/comparison.py)

Зависимости: `dataclasses`, `datetime`, `json`, `cloud_audit.errors`, `cloud_audit.models.history`, `cloud_audit.models.security`.

Поле/константа `OPEN`:

```python
OPEN = {'confirmed_violation', 'potential_risk'}
```

### Функция/метод `runtime_proofs`

[Определение](../src/cloud_audit/services/comparison.py#L17)

Извлекает из evidence время и точные цели allowed/2xx или denied/403; некорректные
доказательства не учитывает.

```python
def runtime_proofs(finding, outcome)
```

### Класс `ReportComparisonService`

[Определение](../src/cloud_audit/services/comparison.py#L44)

Чистая логика сравнения; не обращается к сети или БД.

### Функция/метод `ReportComparisonService.compare`

[Определение](../src/cloud_audit/services/comparison.py#L46)

Проверяет идентичность/namespace/версию/охват/политику/время и классифицирует переходы;
confirmed anonymous resolved требует точных новых отказов.

```python
def compare(self, before: SecurityReport, after: SecurityReport) -> ReportComparison
```

### Функция/метод `ReportComparisonService.compare.context`

[Определение](../src/cloud_audit/services/comparison.py#L101)

Копирует provenance, охват, политику и статусы отчёта в отдельный ComparisonContext.

```python
def context(report)
```

## `src/cloud_audit/services/environment.py`

Готовит локальное состояние и формирует результат проверки окружения через внедряемое хранилище.

[Исходный файл](../src/cloud_audit/services/environment.py)

Зависимости: `dataclasses`, `cloud_audit.interfaces`, `cloud_audit.models.settings`.

### Класс `EnvironmentReport`

[Определение](../src/cloud_audit/services/environment.py#L9)

Результат локальной проверки готовности без облачных ключей.

Поле/константа `EnvironmentReport.status`:

```python
status: str
```

Поле/константа `EnvironmentReport.environment`:

```python
environment: str
```

Поле/константа `EnvironmentReport.log_level`:

```python
log_level: str
```

### Класс `EnvironmentService`

[Определение](../src/cloud_audit/services/environment.py#L16)

Проверка конфигурации и доступности каталогов через StateStorage.

### Функция/метод `EnvironmentService.__init__`

[Определение](../src/cloud_audit/services/environment.py#L18)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, settings: Settings, storage: StateStorage)
```

### Функция/метод `EnvironmentService.check`

[Определение](../src/cloud_audit/services/environment.py#L26)

Готовит каталоги через StateStorage, возвращает status=ok и параметры окружения без ключей.

```python
def check(self) -> EnvironmentReport
```

## `src/cloud_audit/services/history.py`

Предоставляет историю и сравнение сохранённых полных отчётов через внедряемый репозиторий.

[Исходный файл](../src/cloud_audit/services/history.py)

Зависимости: `cloud_audit.interfaces`, `cloud_audit.services.comparison`, `cloud_audit.models.history`.

### Класс `AuditHistoryService`

[Определение](../src/cloud_audit/services/history.py#L8)

Координирует чтение истории и сравнение полных сохранённых отчётов.

### Функция/метод `AuditHistoryService.__init__`

[Определение](../src/cloud_audit/services/history.py#L10)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, repository: AuditHistoryRepository)
```

### Функция/метод `AuditHistoryService.history`

[Определение](../src/cloud_audit/services/history.py#L17)

Передаёт HistoryQuery в репозиторий и возвращает HistoryPage.

```python
def history(self, query: HistoryQuery) -> HistoryPage
```

### Функция/метод `AuditHistoryService.compare`

[Определение](../src/cloud_audit/services/history.py#L21)

Читает два полных отчёта по ID и передаёт их чистому сервису сравнения; фильтрованные
представления не использует.

```python
def compare(self, before_id: str, after_id: str)
```

## `src/cloud_audit/services/profiles.py`

Работа с профилем: подключение, ресурсы, демонстрация и чтение отчёта. Реальные проверки выполняет
отдельный сервис аудита.

[Исходный файл](../src/cloud_audit/services/profiles.py)

Зависимости: `typing`, `uuid`, `cloud_audit.models.resources`, `cloud_audit.models.security`, `cloud_audit.errors`, `cloud_audit.interfaces`.

### Класс `ProfileService`

[Определение](../src/cloud_audit/services/profiles.py#L14)

Сценарии профиля и демонстрации; облачный ресурс не может получить имитированный отчёт.

### Функция/метод `ProfileService.__init__`

[Определение](../src/cloud_audit/services/profiles.py#L16)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, provider: StorageProvider, reports: ReportRepository)
```

### Функция/метод `ProfileService.connection`

[Определение](../src/cloud_audit/services/profiles.py#L24)

Вызывает connect провайдера и возвращает mode/status/безопасное сообщение.

```python
def connection(self) -> dict[str, str]
```

### Функция/метод `ProfileService.resources`

[Определение](../src/cloud_audit/services/profiles.py#L30)

Передаёт запрос списка ресурсов внедрённому провайдеру.

```python
def resources(self) -> tuple[Resource, ...]
```

### Функция/метод `ProfileService.simulate`

[Определение](../src/cloud_audit/services/profiles.py#L34)

Разрешает только mode=demo, находит ресурс, запускает preview, сохраняет демонстрационный
отчёт; vk отклоняет.

```python
def simulate(self, resource_id: str, rules: tuple[str, ...]) -> AuditReport
```

### Функция/метод `ProfileService.report`

[Определение](../src/cloud_audit/services/profiles.py#L49)

Читает ранее сохранённый отчёт через репозиторий без подключения к облаку.

```python
def report(self, report_id: str) -> AuditReport | SecurityReport
```

## `src/cloud_audit/services/scanning.py`

Последовательная обработка нескольких бакетов с независимыми внешним и внутренним этапами.

[Исходный файл](../src/cloud_audit/services/scanning.py)

Зависимости: `dataclasses`, `datetime`, `uuid`, `cloud_audit.errors`, `cloud_audit.interfaces`, `cloud_audit.services.snapshots`, `cloud_audit.services.audit`, `cloud_audit.models.scanning`, `cloud_audit.models.snapshot`, `cloud_audit.rules.external`.

### Класс `ScanService`

[Определение](../src/cloud_audit/services/scanning.py#L15)

Не создаёт SDK/файлы: получает инспектор, репозитории и необязательные авторизованные сервисы извне.

### Функция/метод `ScanService.__init__`

[Определение](../src/cloud_audit/services/scanning.py#L17)

Сохраняет зависимости; отсутствие провайдера означает внешний режим без ключей.

```python
def __init__(self, external: ExternalInspection, repository: ScanRunRepository, provider: ScanProvider | None=None, snapshots: SnapshotService | None=None, audits: SecurityAuditService | None=None)
```

### Функция/метод `ScanService.run`

[Определение](../src/cloud_audit/services/scanning.py#L23)

Выбирает цели, сохраняет отдельные ошибки и общий результат; мутации не включаются автоматически при обнаружении бакета.

```python
def run(self, targets, *, all_buckets=False, max_objects=20, external_only=False, mutation_buckets=(), allow_residue=False, selection_source='explicit', default_policy=None)
```

### Функция/метод `ScanService._bucket`

[Определение](../src/cloud_audit/services/scanning.py#L56)

Ошибка или запрет внешнего этапа не подавляет внутренний; ошибка одного бакета не прерывает другие.

```python
def _bucket(self, target, limit, external_only)
```

### Функция/метод `ScanService._observation`

[Определение](../src/cloud_audit/services/scanning.py#L107)

Переносит только доказанные исходы проб в evidence внутреннего отчёта; пропуски становятся error, не allowed.

```python
def _observation(probe)
```

## `src/cloud_audit/services/snapshots.py`

Оркестрирует сбор и сохранение снимка; фиксирует начало последовательного, не атомарного наблюдения
и namespace провайдера.

[Исходный файл](../src/cloud_audit/services/snapshots.py)

Зависимости: `datetime`, `uuid`, `cloud_audit.interfaces`, `cloud_audit.errors`, `cloud_audit.models.resources`, `cloud_audit.models.snapshot`.

### Класс `SnapshotService`

[Определение](../src/cloud_audit/services/snapshots.py#L15)

Собирает снимок через коллектор и сохраняет его через независимый репозиторий.

### Функция/метод `SnapshotService.__init__`

[Определение](../src/cloud_audit/services/snapshots.py#L17)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, collector: ConfigurationCollector, repository: SnapshotRepository)
```

### Функция/метод `SnapshotService.collect`

[Определение](../src/cloud_audit/services/snapshots.py#L25)

Фиксирует начало сбора, создаёт Resource, вызывает коллектор, вычисляет полноту/охват и
сохраняет снимок v1/v2.

```python
def collect(self, resource_id: str, options: CollectionOptions | None=None) -> ConfigurationSnapshot
```

### Функция/метод `SnapshotService.enrich`

[Определение](../src/cloud_audit/services/snapshots.py#L47)

Сохраняет новый снимок с фактами внешнего этапа и пересчитанной полнотой, не меняя старый ID.

```python
def enrich(self, snapshot, observations)
```

## `src/cloud_audit/storage/__init__.py`

Сохранение состояния, история и проверка сериализованных данных.

[Исходный файл](../src/cloud_audit/storage/__init__.py)

## `src/cloud_audit/storage/json_reports.py`

Совместимое JSON-хранилище прежних отчётов, общий декодер и перечисление источников для явного
импорта в SQLite.

[Исходный файл](../src/cloud_audit/storage/json_reports.py)

Зависимости: `dataclasses`, `json`, `os`, `pathlib`, `re`, `tempfile`, `cloud_audit.errors`, `cloud_audit.models.resources`, `cloud_audit.models.security`, `cloud_audit.storage.report_schema`.

### Функция/метод `decode_report`

[Определение](../src/cloud_audit/storage/json_reports.py#L18)

Выбирает demo/vk декодер, проверяет ID и реконструирует модели; ошибки данных выдаёт как AuditError.

```python
def decode_report(data: dict, report_id: str) -> AuditReport | SecurityReport
```

### Класс `JsonReportRepository`

[Определение](../src/cloud_audit/storage/json_reports.py#L34)

Читает и записывает совместимые JSON-отчёты; используется также при импорте прежних данных.

### Функция/метод `JsonReportRepository.__init__`

[Определение](../src/cloud_audit/storage/json_reports.py#L36)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, directory: Path)
```

### Функция/метод `JsonReportRepository._path`

[Определение](../src/cloud_audit/storage/json_reports.py#L43)

Проверяет UUID hex до построения пути REPORT_ID.json, исключая выход из каталога.

```python
def _path(self, report_id: str) -> Path
```

### Функция/метод `JsonReportRepository.save`

[Определение](../src/cloud_audit/storage/json_reports.py#L49)

Пишет отчёт во временный приватный файл и атомарно заменяет JSON; используется для
совместимости и тестовых данных.

```python
def save(self, report: AuditReport | SecurityReport) -> None
```

### Функция/метод `JsonReportRepository.get`

[Определение](../src/cloud_audit/storage/json_reports.py#L66)

Читает UTF-8 JSON и реконструирует модели общим декодером; отсутствие/повреждение выдаёт
контролируемой ошибкой.

```python
def get(self, report_id: str) -> AuditReport | SecurityReport
```

### Функция/метод `JsonReportRepository.identifiers`

[Определение](../src/cloud_audit/storage/json_reports.py#L80)

Перечисляет только нессылочные *.json с UUID hex для явного импорта; другие артефакты не
импортирует.

```python
def identifiers(self) -> tuple[str, ...]
```

## `src/cloud_audit/storage/report_schema.py`

Декодирует SecurityReport v1/v2/v3 и проверяет согласованность статусов, риска и доказательств.

[Исходный файл](../src/cloud_audit/storage/report_schema.py)

Зависимости: `datetime`, `json`, `re`, `cloud_audit.models.resources`, `cloud_audit.models.security`, `cloud_audit.configuration.policy`, `cloud_audit.models.snapshot`.

### Функция/метод `decode_security_report`

[Определение](../src/cloud_audit/storage/report_schema.py#L12)

Восстанавливает v1/v2/v3, проверяет риск/статусы, обязательные доказательства и согласованность
известных правил; при ошибке ValueError.

```python
def decode_security_report(data: dict) -> SecurityReport
```

## `src/cloud_audit/storage/scans.py`

Версионированные приватные сводки scan: атомарное сохранение и строгое чтение без сети.

[Исходный файл](../src/cloud_audit/storage/scans.py)

Зависимости: `dataclasses`, `pathlib`, `types`, `typing`, `json`, `os`, `re`, `tempfile`, `cloud_audit.errors`, `cloud_audit.models.scanning`, `cloud_audit.rules.external`, `cloud_audit.configuration.policy`.

### Функция/метод `decode_value`

[Определение](../src/cloud_audit/storage/scans.py#L17)

Восстанавливает только известные dataclass/tuple/скаляры со строгими типами, не исполняя JSON.

```python
def decode_value(value, annotation)
```

### Класс `JsonScanRepository`

[Определение](../src/cloud_audit/storage/scans.py#L41)

Сохраняет общую сводку отдельно от SQLite-отчётов бакетов, без изменения прежней схемы БД.

Поле/константа `JsonScanRepository.MAX_BYTES`:

```python
MAX_BYTES = 32 * 1024 * 1024
```

### Функция/метод `JsonScanRepository.__init__`

[Определение](../src/cloud_audit/storage/scans.py#L45)

Принимает выделенный приватный каталог сводок.

```python
def __init__(self, directory: Path)
```

### Функция/метод `JsonScanRepository._path`

[Определение](../src/cloud_audit/storage/scans.py#L49)

Проверяет UUID до построения пути.

```python
def _path(self, identifier)
```

### Функция/метод `JsonScanRepository.save`

[Определение](../src/cloud_audit/storage/scans.py#L55)

Атомарно публикует новый файл 0600 без перезаписи другого результата с тем же ID.

```python
def save(self, run: ScanRun)
```

### Функция/метод `JsonScanRepository.get`

[Определение](../src/cloud_audit/storage/scans.py#L82)

Читает и проверяет форму/версию/вложенные типы; повреждённые сводки не становятся пустым успехом.

```python
def get(self, identifier)
```

### Функция/метод `JsonScanRepository._validate`

[Определение](../src/cloud_audit/storage/scans.py#L97)

Проверяет согласованность сохранённых выводов с пробами и контекстом, а не только тип JSON.

```python
def _validate(run)
```

## `src/cloud_audit/storage/snapshot_schema.py`

Проверяет нормализованные значения восьми настроек, ACL объектов и метаданные проб до повторного
анализа снимка.

[Исходный файл](../src/cloud_audit/storage/snapshot_schema.py)

Зависимости: `dataclasses`, `datetime`, `re`, `cloud_audit.models.snapshot`.

Поле/константа `SOURCES`:

```python
SOURCES = {'bucket_acl': 'get_bucket_acl', 'bucket_policy': 'get_bucket_policy', 'public_access_block': 'get_public_access_block', 'ownership_controls': 'get_bucket_ownership_controls', 'versioning': 'get_bucket_versioning', 'logging': 'get_bucket_logging', 'encryption': 'get_bucket_encryption', 'object_lock': 'get_object_lock_configuration'}
```

Поле/константа `REASONS`:

```python
REASONS = {'absent': {'not_configured'}, 'access_denied': {'permission_required'}, 'unsupported': {'api_not_supported'}, 'error': {'rate_limit', 'service_error', 'sdk_or_network_error', 'invalid_response'}, 'not_found': {'resource_not_found'}}
```

### Функция/метод `validate_observation`

[Определение](../src/cloud_audit/storage/snapshot_schema.py#L27)

Проверяет типы и допустимые значения нормализованного наблюдения; не интерпретирует семантику
политики доступа.

```python
def validate_observation(item: ConfigurationObservation) -> None
```

## `src/cloud_audit/storage/snapshots.py`

Атомарные приватные JSON-снимки v1/v2, лимит 2 МиБ и хранение семь суток; повреждённые данные не
становятся безопасной конфигурацией.

[Исходный файл](../src/cloud_audit/storage/snapshots.py)

Зависимости: `dataclasses`, `datetime`, `json`, `os`, `pathlib`, `re`, `tempfile`, `typing`, `cloud_audit.errors`, `cloud_audit.models.resources`, `cloud_audit.models.snapshot`, `cloud_audit.storage.snapshot_schema`.

### Класс `JsonSnapshotRepository`

[Определение](../src/cloud_audit/storage/snapshots.py#L24)

Проверяет и хранит снимки, соблюдая лимит размера, TTL и атомарность записи.

Поле/константа `JsonSnapshotRepository.RETENTION`:

```python
RETENTION = timedelta(days=7)
```

Поле/константа `JsonSnapshotRepository.MAX_BYTES`:

```python
MAX_BYTES = 2 * 1024 * 1024
```

### Функция/метод `JsonSnapshotRepository.__init__`

[Определение](../src/cloud_audit/storage/snapshots.py#L29)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, directory: Path, clock: Callable[[], datetime] | None=None)
```

### Функция/метод `JsonSnapshotRepository._path`

[Определение](../src/cloud_audit/storage/snapshots.py#L37)

Проверяет UUID hex и строит путь снимка.

```python
def _path(self, snapshot_id: str) -> Path
```

### Функция/метод `JsonSnapshotRepository._decode`

[Определение](../src/cloud_audit/storage/snapshots.py#L43)

Проверяет версии/охват/обязательные наблюдения/время/схему/полноту и восстанавливает
ConfigurationSnapshot.

```python
def _decode(self, raw: str, expected_id: str) -> ConfigurationSnapshot
```

### Функция/метод `JsonSnapshotRepository.save`

[Определение](../src/cloud_audit/storage/snapshots.py#L90)

Проверяет снимок и лимит 2 МиБ, удаляет просроченные, выполняет приватную запись с fsync и
атомарной заменой.

```python
def save(self, snapshot: ConfigurationSnapshot) -> None
```

### Функция/метод `JsonSnapshotRepository._read`

[Определение](../src/cloud_audit/storage/snapshots.py#L118)

Отклоняет симлинк/слишком большой файл, читает UTF-8 и вызывает строгий декодер.

```python
def _read(self, path: Path) -> ConfigurationSnapshot
```

### Функция/метод `JsonSnapshotRepository.get`

[Определение](../src/cloud_audit/storage/snapshots.py#L124)

Читает валидный непросроченный снимок; отсутствие, неверный UTF-8 и истечение TTL выдаёт
AuditError.

```python
def get(self, snapshot_id: str) -> ConfigurationSnapshot
```

### Функция/метод `JsonSnapshotRepository._expired`

[Определение](../src/cloud_audit/storage/snapshots.py#L140)

Сравнивает время сбора с внедрёнными часами и RETENTION=7 суток.

```python
def _expired(self, snapshot: ConfigurationSnapshot) -> bool
```

### Функция/метод `JsonSnapshotRepository._purge_expired`

[Определение](../src/cloud_audit/storage/snapshots.py#L144)

При сохранении удаляет только распознанные валидные просроченные снимки;
неизвестные/повреждённые файлы не трогает.

```python
def _purge_expired(self) -> None
```

## `src/cloud_audit/storage/sqlite.py`

Транзакционная история SQLite: неизменяемые ID, полные отчёты, failed-запуски без находок, фильтры и
явный импорт JSON.

[Исходный файл](../src/cloud_audit/storage/sqlite.py)

Зависимости: `collections`, `contextlib`, `dataclasses`, `datetime`, `json`, `os`, `pathlib`, `re`, `sqlite3`, `uuid`, `cloud_audit.errors`, `cloud_audit.models.resources`, `cloud_audit.models.history`, `cloud_audit.models.security`, `cloud_audit.storage.json_reports`.

Поле/константа `SCHEMA`:

```python
SCHEMA = '\nCREATE TABLE IF NOT EXISTS runs (\n id TEXT PRIMARY KEY, mode TEXT NOT NULL, resource_id TEXT NOT NULL, resource_name TEXT NOT NULL,\n observed_at TEXT, recorded_at TEXT NOT NULL, run_status TEXT NOT NULL,\n parameters TEXT NOT NULL, payload TEXT, error_code TEXT\n);\nCREATE TABLE IF NOT EXISTS run_rules (\n run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, rule_id TEXT NOT NULL,\n position INTEGER NOT NULL, status TEXT, severity TEXT, PRIMARY KEY(run_id, rule_id)\n);\nCREATE INDEX IF NOT EXISTS runs_resource_time ON runs(mode, resource_id, observed_at DESC);\nCREATE INDEX IF NOT EXISTS rules_filters ON run_rules(rule_id, severity, status, run_id);\n'
```

### Функция/метод `utc`

[Определение](../src/cloud_audit/storage/sqlite.py#L38)

Приводит ISO-время с timezone к UTC для устойчивой сортировки в SQLite.

```python
def utc(value)
```

### Класс `SqliteReportRepository`

[Определение](../src/cloud_audit/storage/sqlite.py#L43)

Основной репозиторий отчётов и истории, включая отдельные неудачные запуски.

Поле/константа `SqliteReportRepository.MAX_REPORT_BYTES`:

```python
MAX_REPORT_BYTES = 32 * 1024 * 1024
```

### Функция/метод `SqliteReportRepository.__init__`

[Определение](../src/cloud_audit/storage/sqlite.py#L47)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, path: Path, legacy: JsonReportRepository | None=None)
```

### Функция/метод `SqliteReportRepository._connection`

[Определение](../src/cloud_audit/storage/sqlite.py#L56)

Создаёт приватную БД, проверяет user_version, включает FK, открывает транзакцию и всегда
закрывает соединение; sqlite-ошибки скрывает за OSError.

```python
def _connection(self)
```

### Функция/метод `SqliteReportRepository._identifier`

[Определение](../src/cloud_audit/storage/sqlite.py#L89)

Требует строковый UUID hex; некорректный ID отклоняет до запроса.

```python
def _identifier(self, value)
```

### Функция/метод `SqliteReportRepository.save`

[Определение](../src/cloud_audit/storage/sqlite.py#L94)

Сохраняет канонический отчёт через общую транзакционную реализацию _save.

```python
def save(self, report) -> None
```

### Функция/метод `SqliteReportRepository._save`

[Определение](../src/cloud_audit/storage/sqlite.py#L98)

Проверяет лимит 32 МиБ/схему, сохраняет runs+run_rules атомарно; одинаковый ID/JSON
идемпотентен, конфликт запрещён.

```python
def _save(self, report) -> bool
```

### Функция/метод `SqliteReportRepository.get`

[Определение](../src/cloud_audit/storage/sqlite.py#L131)

Читает и проверяет полный отчёт из БД; при отсутствии ID обращается к legacy, failed без
payload отклоняет.

```python
def get(self, report_id)
```

### Функция/метод `SqliteReportRepository.record_failure`

[Определение](../src/cloud_audit/storage/sqlite.py#L150)

Записывает безопасную категорию сбоя, выбранные правила/объекты/namespace, без находок и без
фиктивного отчёта.

```python
def record_failure(self, resource_id, selected_rules, object_keys, error_code, resource_namespace=None)
```

### Функция/метод `SqliteReportRepository.history`

[Определение](../src/cloud_audit/storage/sqlite.py#L168)

Валидирует фильтры/пагинацию, применяет параметры SQL к одной находке, возвращает total,
полный счётчик статусов и страницу.

```python
def history(self, query: HistoryQuery) -> HistoryPage
```

### Функция/метод `SqliteReportRepository.import_legacy`

[Определение](../src/cloud_audit/storage/sqlite.py#L208)

Явно импортирует совместимые UUID-JSON, оставляя источники; повторный импорт идемпотентен,
повреждённые/конфликтующие ID перечисляет в skipped.

```python
def import_legacy(self)
```

## `src/cloud_audit/storage/state.py`

Готовит выделенные каталоги состояния с правами 0700 и проверяет возможность записи.

[Исходный файл](../src/cloud_audit/storage/state.py)

Зависимости: `pathlib`, `tempfile`.

### Класс `LocalStateStorage`

[Определение](../src/cloud_audit/storage/state.py#L6)

Файловая реализация подготовки выделенного каталога состояния.

### Функция/метод `LocalStateStorage.__init__`

[Определение](../src/cloud_audit/storage/state.py#L8)

Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
выполняются отдельными методами.

```python
def __init__(self, root: Path)
```

### Функция/метод `LocalStateStorage.prepare`

[Определение](../src/cloud_audit/storage/state.py#L15)

Создаёт/закрывает root,data,logs до 0700 и проверяет возможность временной записи в каждом
каталоге.

```python
def prepare(self) -> None
```

## `scripts/build_code_reference.py`

Build the complete source reference from AST and checked-in module/function docstrings.

[Исходный файл](../scripts/build_code_reference.py)

Зависимости: `argparse`, `ast`, `pathlib`.

Поле/константа `ROOT`:

```python
ROOT = Path(__file__).resolve().parents[1]
```

Поле/константа `TARGET`:

```python
TARGET = ROOT / 'docs' / 'CODE_REFERENCE.md'
```

### Функция/метод `render_module`

[Определение](../scripts/build_code_reference.py#L10)

Describe a source file, its imports, constants, classes, fields and every named function.

```python
def render_module(path: Path) -> list[str]
```

### Функция/метод `render_module.definitions`

[Определение](../scripts/build_code_reference.py#L25)

Recursively render class fields, methods and local named helpers without executing source.

```python
def definitions(nodes, prefix='')
```

### Функция/метод `build_reference`

[Определение](../scripts/build_code_reference.py#L59)

Read only tracked-style Python source locations; configuration and runtime state are never scanned.

```python
def build_reference() -> str
```

### Функция/метод `main`

[Определение](../scripts/build_code_reference.py#L75)

Regenerate CODE_REFERENCE.md, or return a nonzero code if --check finds it stale.

```python
def main() -> int
```

## `scripts/verify_public_access.py`

Isolated VK Cloud read/list fixture. Creates only artificial data; always attempts cleanup.

[Исходный файл](../scripts/verify_public_access.py)

Зависимости: `argparse`, `json`, `os`, `pathlib`, `uuid`, `time`, `botocore.exceptions`, `botocore.parsers`, `cloud_audit.rules.registry`, `cloud_audit.rules.engine`, `cloud_audit.services.audit`, `cloud_audit.services.snapshots`, `cloud_audit.models.security`, `cloud_audit.models.snapshot`, `cloud_audit.configuration.environment`, `cloud_audit.configuration.dotenv`, `cloud_audit.providers.s3`, `cloud_audit.storage.snapshots`, `cloud_audit.storage.json_reports`, `cloud_audit.storage.sqlite`, `cloud_audit.storage.state`.

### Функция/метод `main`

[Определение](../scripts/verify_public_access.py#L26)

Создаёт только новый искусственный стенд, проверяет private/public/private и всегда пытается удалить созданные ресурсы; возвращает 0 либо 2.

```python
def main()
```

### Функция/метод `main.run_stage`

[Определение](../scripts/verify_public_access.py#L44)

Собирает свежий снимок с unsigned read/list, выполняет четыре анонимных правила и сохраняет безопасную сводку стадии.

```python
def run_stage(name)
```

### Функция/метод `main.verify_stage`

[Определение](../scripts/verify_public_access.py#L56)

Собирает до пяти свежих наблюдений с паузой секунду; сохраняет каждую попытку и не подменяет ожидаемое состояние фактическим.

```python
def verify_stage(name, opened=False)
```

## `scripts/verify_staged_scan.py`

Изолированный трёхбакетный стенд scan: закрыто/публично/закрыто, только искусственные данные.

[Исходный файл](../scripts/verify_staged_scan.py)

Зависимости: `argparse`, `json`, `os`, `pathlib`, `subprocess`, `sys`, `time`, `uuid`, `botocore.exceptions`, `botocore.parsers`, `cloud_audit.configuration.environment`, `cloud_audit.configuration.dotenv`, `cloud_audit.providers.s3`, `cloud_audit.reports.formatting`, `cloud_audit.storage.state`.

Поле/константа `ERRORS`:

```python
ERRORS = (ClientError, BotoCoreError, ResponseParserError, OSError, ValueError, KeyError, TypeError)
```

### Функция/метод `cleanup_fixture`

[Определение](../scripts/verify_staged_scan.py#L23)

Закрывает и удаляет только успешно созданные этим запуском бакеты, продолжая после ошибок.

```python
def cleanup_fixture(client, owned)
```

### Функция/метод `public_phase_confirmed`

[Определение](../scripts/verify_staged_scan.py#L49)

Подтверждает существование каждой публичной операции по отдельным исходным запускам, не создавая объединённого фиктивного отчёта.

```python
def public_phase_confirmed(attempts, names, key)
```

### Функция/метод `main`

[Определение](../scripts/verify_staged_scan.py#L74)

Создаёт отдельный стенд с явным флагом, запускает реальный CLI и записывает приватную сводку всех попыток.

```python
def main()
```

### Функция/метод `main.invoke`

[Определение](../scripts/verify_staged_scan.py#L92)

Запускает публичный CLI отдельным процессом; сохраняет только контролируемые факты и идентификаторы.

```python
def invoke(label, file, unsigned=False)
```

### Функция/метод `main.matches`

[Определение](../scripts/verify_staged_scan.py#L112)

Требует реальные исходы запросов, а не только наличие разрешающих настроек.

```python
def matches(run, opened)
```

### Функция/метод `main.settled`

[Определение](../scripts/verify_staged_scan.py#L133)

Даёт политике до пяти ограниченных попыток применения, не скрывая неуспешные наблюдения.

```python
def settled(label, opened)
```

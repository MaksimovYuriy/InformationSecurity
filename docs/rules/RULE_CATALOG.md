# Окончательный набор правил основной версии

Для VK Cloud выбраны восемь проверок. Правила независимы по угрозе или операции; статус каждого зависит от доступных данных и согласованного контекста.

| ID | Проверка | Источники | Карточка |
|---|---|---|---|
| bucket-versioning-enabled | Сохранение версий после изменений | versioning | [Версионирование](BUCKET_VERSIONING.md) |
| anonymous-read | Анонимное чтение содержимого | policy, object ACL, ownership, unsigned GetObject | [Анонимные операции](ANONYMOUS_ACCESS.md) |
| anonymous-list | Анонимное получение списка | policy, bucket ACL, ownership, unsigned ListObjects | [Анонимные операции](ANONYMOUS_ACCESS.md) |
| anonymous-write | Анонимная загрузка/перезапись | policy, bucket WRITE, отдельно включённая проба | [Анонимные операции](ANONYMOUS_ACCESS.md) |
| anonymous-delete | Анонимное удаление | policy, bucket WRITE, отдельно включённая проба | [Анонимные операции](ANONYMOUS_ACCESS.md) |
| unapproved-external-access | Неутверждённые именованные внешние гранты | policy/ACL и доверенные/допустимые субъекты | [Управление доступом](GOVERNANCE_ACCESS.md#unapproved-external-access) |
| excess-explicit-permissions | Явные права сверх необходимой модели | policy/ACL и required_permissions | [Управление доступом](GOVERNANCE_ACCESS.md#excess-explicit-permissions) |
| bucket-acl-disabled | Защита от случайного открытия через ACL | Ownership Controls | [Управление доступом](GOVERNANCE_ACCESS.md#bucket-acl-disabled) |

Журналирование и шифрование не включены в обязательный набор: соответствующие S3 API на стенде вернули unsupported. Нельзя выдавать это за отсутствие механизмов у провайдера. HTTP-транспорт не проверяется одним фактом HTTPS endpoint; полноценную проверку политики транспорта не подменяем таким правилом. Object Lock отличается от версионирования, но обязательность неизменяемого хранения для всех учебных бакетов не установлена.

Для каждого правила в карточках указаны угроза, входные данные, алгоритм, исключения/ограничения, оценка риска, рекомендация и способ подтверждения. Внешний доступ и избыточность ограничены явными грантами в выбранном охвате; это не весь IAM проекта. Отсутствие необходимого контекста не считается успешной проверкой.

## Матрица проверок итерации 7

| Новое правило | Безопасный сценарий | Ошибочный сценарий | Неполные данные |
|---|---|---|---|
| unapproved-external-access | собственный/разрешённый проект, точный разрешённый ARN, известный Deny | чужой CanonicalUser или неутверждённый проект, AuthenticatedUsers | нет trusted_project_ids для named-политики, отказ доступа, Condition |
| excess-explicit-permissions | явное чтение при baseline read, известный запрет DeleteObject | лишний delete/write_acl, права через проект или AuthenticatedUsers | нет baseline, субъект не наблюдался, неучтённые внутренние права, неизвестное действие |
| bucket-acl-disabled | BucketOwnerEnforced | Preferred при требовании acl_disabled; иначе потенциальный риск | нет/неизвестны Ownership Controls |

Прежние пять правил и их сценарии описаны в протоколах итераций 5–6. Их полный набор тестов в итерации 7 не перезапускался по согласованному режиму проверок.

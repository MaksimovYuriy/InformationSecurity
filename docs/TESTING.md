# Тестирование основной части

## Запуск

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/build_code_reference.py --check
```

Все тесты — стандартный unittest. Реальная сеть в наборе не используется: адаптеры получают Mock/Stubber, CLI запускается отдельными процессами. Живой стенд запускается явно по USER_GUIDE. Полный набор разрешён пользователем для итерации 10.

Отдельный файл: `PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p test_report_comparison.py -v`. Имена отражают поведение, не историю разработки. Старый одноразовый run_iteration09.py удалён; приёмка теперь обычный test_acceptance.py.

## Общие данные

`audit_fixtures.py`: snapshot — минимальный факт версионирования; config — искусственный бакет с ACL/политикой; grant/statement/named_statement — гранты; configured_client/failure — SDK-ответы и безопасные ошибки; version_report — настоящий отчёт движка на искусственных данных. Тестовые модули не импортируют друг друга. `test_acceptance.py` отдельно строит полный валидный снимок и запускает CLI без ключей.

## Полный перечень тестов

Названия методов формулируют ожидаемый сценарий; исходные assertions доступны по ссылке на файл. Каждый прежний сценарий сохранён при переносе, новые структурные проверки добавлены отдельно.

| Файл | Что проверяет | Методов |
|---|---|---|
| [test_acceptance.py](../tests/test_acceptance.py) | Сквозная матрица восьми правил, CLI без ключей, недостаток данных, ошибки, история и подтверждение исправления. | 8 |
| [test_access_cli.py](../tests/test_access_cli.py) | Свежий CLI-аудит с внедрёнными SDK-ответами, выбор объектов/проб и целостность подтверждений. | 3 |
| [test_access_collection.py](../tests/test_access_collection.py) | ACL выбранных объектов, unsigned-транспорт, ограничение чтения, изоляция/уборка write/delete. | 12 |
| [test_audit_history.py](../tests/test_audit_history.py) | SQLite, неизменяемость ID, фильтры/пагинация, импорт JSON, транзакции и ошибки БД. | 10 |
| [test_bootstrap.py](../tests/test_bootstrap.py) | Настройки, check, версия, закрытые каталоги и отсутствие секретов. | 5 |
| [test_cli_workflow.py](../tests/test_cli_workflow.py) | Демонстрационный сценарий между процессами и ошибки аргументов. | 3 |
| [test_configuration_snapshot.py](../tests/test_configuration_snapshot.py) | Восемь настроек, нормализация, причины недоступности, схема, TTL, атомарная запись и CLI. | 13 |
| [test_evidence_integrity.py](../tests/test_evidence_integrity.py) | Повреждённые данные/время/UTF-8/XML не создают ложный безопасный отчёт. | 4 |
| [test_fixture_verification.py](../tests/test_fixture_verification.py) | Ограниченное ожидание публикации/закрытия политики, сохранение попыток и уборка при исчерпании лимита. | 3 |
| [test_fixture_cleanup.py](../tests/test_fixture_cleanup.py) | Удаление созданного бакета даже при сбое создания искусственного объекта. | 1 |
| [test_governance_rules.py](../tests/test_governance_rules.py) | Внешние субъекты, инвентарь грантов, baseline необходимых прав, Deny, ACL и границы IAM. | 18 |
| [test_governance_workflow.py](../tests/test_governance_workflow.py) | Политика управления доступом, реестр, отчёты, исключения и офлайн-CLI. | 6 |
| [test_history_cli.py](../tests/test_history_cli.py) | Импорт, история, фильтрованный экспорт, сравнение и failed-запуски через CLI. | 3 |
| [test_package_structure.py](../tests/test_package_structure.py) | Предметные пакеты, направление зависимостей, логические имена тестов и документация определений. | 4 |
| [test_public_access.py](../tests/test_public_access.py) | Семантика политик/ACL и unsigned-фактов для четырёх анонимных операций. | 10 |
| [test_report_comparison.py](../tests/test_report_comparison.py) | Переходы находок, provenance, охват, политика, время и точные цели подтверждения исправления. | 8 |
| [test_report_formatting.py](../tests/test_report_formatting.py) | Неизменяемость фильтра, экранирование Markdown, доказательства и приватный экспорт без перезаписи. | 3 |
| [test_rule_engine.py](../tests/test_rule_engine.py) | Регистрация/выбор правил, применимость, required_data, риск, исключения и расширяемость. | 7 |
| [test_s3_provider.py](../tests/test_s3_provider.py) | Подключение SDK, страницы бакетов, валидация endpoint/ключей и безопасные ошибки. | 7 |
| [test_security_workflow.py](../tests/test_security_workflow.py) | Настоящий аудит, строгая политика, самодостаточный отчёт и его проверка/офлайн-чтение. | 6 |

| [test_staged_scan.py](../tests/test_staged_scan.py) | Независимые этапы/бакеты, выбор целей, per-bucket разрешения, обогащённые снимки и восстановление фактов. | 8 |
| [test_staged_probes.py](../tests/test_staged_probes.py) | Ограниченное перечисление, фактические unsigned-запросы, эффект DELETE, владение/уборка и особенности metadata/null-версии. | 15 |
| [test_staged_cli.py](../tests/test_staged_cli.py) | Режимы ключей, scan/scan-report, приватность/согласованность сводок и полный pipeline двух бакетов. | 7 |
| [test_staged_fixture.py](../tests/test_staged_fixture.py) | Ограниченный реальный стенд, owned-уборка и подтверждения операций из отдельных исходных запусков. | 3 |

| [test_local_environment.py](../tests/test_local_environment.py) | Безопасная автозагрузка .env, приоритет окружения, ошибки, CLI и установленный launcher без PYTHONPATH. | 7 |

Всего явно объявлено **174 тестовых методов**. Подсценарии subTest (в том числе 24 сочетания приёмочной матрицы) в это число отдельно не прибавляются.

### `test_acceptance.py`

Класс `AcceptanceTests`:

- `test_rule_matrix_private_risky_and_unavailable_through_cli`
- `test_exception_keeps_violation_and_changed_coverage_cannot_resolve`
- `test_fresh_remediation_history_export_and_repeated_snapshot`
- `test_cloud_error_history_never_creates_a_clean_report`
- `test_api_errors_and_unknown_conditions_remain_unverified`
- `test_default_eight_rules_persist_and_check_runs_without_cloud_credentials`
- `test_no_selected_objects_never_means_read_access_was_checked`
- `test_live_cli_collection_failures_are_recorded_without_false_remediation`

### `test_access_cli.py`

Класс `AccessCliTests`:

- `test_live_cli_selection_and_probes_roundtrip_all_eight_rules`
- `test_probe_flags_cannot_mutate_offline_or_demo_or_without_opt_in`

Класс `AccessReportIntegrityTests`:

- `test_confirmed_access_requires_a_positive_unsigned_request_in_saved_evidence`

### `test_access_collection.py`

Класс `AccessCollectionTests`:

- `test_only_explicit_objects_are_collected_without_list_or_content_reads`
- `test_missing_object_and_acl_denial_remain_distinct`
- `test_unsigned_reads_are_bounded_and_body_is_closed_without_persisting_contents`
- `test_anonymous_404_is_unknown_not_a_denied_or_safe_result`
- `test_options_require_explicit_write_opt_in_and_limit_object_scope`

Класс `ProbeSafetyTests`:

- `test_factory_is_unsigned_even_when_environment_contains_credentials`
- `test_mutations_need_opt_in_and_cleanup_exact_created_versions_and_markers`
- `test_fixture_access_denial_and_cleanup_failure_are_recorded_not_leaked`
- `test_extended_snapshot_and_report_roundtrip_keep_scope_and_probe_evidence`

Класс `MutationIsolationTests`:

- `test_preexisting_versions_are_never_deleted_or_overwritten_by_probe`

Класс `CleanupFailureTests`:

- `test_cleanup_failure_after_probe_is_explicit_and_preserves_positive_evidence`

Класс `UnsignedTransportTests`:

- `test_serialized_sdk_requests_have_no_authorization_or_credential_query`

### `test_audit_history.py`

Класс `StorageTests`:

- `test_persists_report_parameters_and_findings_across_connections_with_private_permissions`
- `test_filters_match_same_finding_and_support_pagination`
- `test_legacy_import_is_explicit_idempotent_and_does_not_delete_json`
- `test_conflicting_id_is_rejected_and_database_keeps_original`
- `test_failed_run_is_recorded_without_fabricated_findings`
- `test_corrupt_database_and_unsupported_version_have_controlled_errors`

Класс `TransactionTests`:

- `test_database_failure_rolls_back_run_and_findings_without_exposing_sql_message`

Класс `HistoryIntegrityTests`:

- `test_rule_and_severity_must_match_the_same_finding`
- `test_invalid_legacy_file_is_reported_and_preserved`
- `test_history_path_cannot_follow_a_symlink`

### `test_bootstrap.py`

Класс `BootstrapTests`:

- `test_defaults_are_local_and_safe`
- `test_invalid_configuration_does_not_expose_value`
- `test_environment_check_creates_private_directories`
- `test_cli_reports_version_and_configuration_without_secrets`
- `test_cli_configuration_error_has_nonzero_exit`

### `test_cli_workflow.py`

Класс `ConsoleWorkflowTests`:

- `test_demo_workflow_persists_report_between_processes`
- `test_invalid_inputs_fail_without_traceback`
- `test_demo_requires_target_and_cli_rejects_unknown_format`

### `test_configuration_snapshot.py`

Класс `CollectionTests`:

- `test_normalizes_data_preserves_policy_conditions_and_excludes_sdk_metadata`
- `test_partial_data_keeps_denied_unsupported_and_network_errors_distinct`
- `test_missing_bucket_or_invalid_credentials_abort_without_saving`
- `test_malformed_data_does_not_become_an_absent_or_safe_configuration`
- `test_service_makes_scope_and_collection_time_explicit`

Класс `SnapshotRepositoryTests`:

- `test_roundtrip_permissions_identifier_and_corruption_validation`
- `test_expired_snapshots_are_rejected_and_removed_on_next_save`

Класс `SnapshotCliTests`:

- `test_collect_partial_snapshot_and_read_offline_in_another_process`

Класс `ConfigurationEvidenceTests`:

- `test_omitted_mfa_delete_setting_is_unknown_not_disabled`
- `test_atomic_write_failure_preserves_previous_snapshot_and_cleans_temporary_file`

Класс `SnapshotSchemaTests`:

- `test_replay_rejects_corrupted_normalized_evidence`

Класс `AdditionalConfigurationTests`:

- `test_present_encryption_logging_and_retention_normalize_without_sdk_metadata`
- `test_rate_limits_and_generic_404_do_not_mean_missing_configuration`

### `test_evidence_integrity.py`

Класс `EvidenceIntegrityTests`:

- `test_invalid_utf8_report_is_a_controlled_error`
- `test_report_cannot_claim_passed_without_observed_enabled_value`
- `test_future_snapshot_timestamp_cannot_bypass_retention`

Класс `MalformedSdkResponseTests`:

- `test_invalid_xml_is_a_sanitized_error_for_all_cloud_read_paths`

### `test_fixture_cleanup.py`

Класс `FixtureCleanupTests`:

- `test_empty_owned_bucket_is_deleted_even_when_object_creation_failed`

### `test_governance_rules.py`

Класс `ExternalAccessTests`:

- `test_unapproved_project_is_risk_and_approved_project_or_subject_is_allowed`
- `test_policy_subject_cannot_be_classified_without_own_project_context`
- `test_owner_is_trusted_but_foreign_object_owner_is_not_automatically_trusted`
- `test_deny_blocks_named_allow_and_acl_but_conditions_prevent_safe_conclusion`
- `test_all_users_is_other_rule_but_authenticated_users_is_external_group`
- `test_unavailable_data_and_enforced_acl_semantics`

Класс `ExcessPermissionsTests`:

- `test_required_baseline_is_mandatory_and_overbroad_grant_is_evidence`
- `test_acl_bucket_write_expands_to_delete_while_object_full_control_does_not`
- `test_wildcard_unknown_actions_and_conditional_denies_are_not_full_pass`
- `test_project_grant_and_user_specific_deny_are_evaluated_for_requested_user`
- `test_implicit_internal_permissions_prevent_global_least_privilege_claim`

Класс `AclDisabledTests`:

- `test_enforced_is_passed_and_preferred_is_risk_or_baseline_violation`
- `test_missing_ownership_is_unknown_and_exception_does_not_hide_it`

Класс `GovernanceBoundariesTests`:

- `test_unobserved_subject_and_missing_project_context_are_incomplete`
- `test_private_owner_acl_without_object_selection_is_not_external_exposure`
- `test_ignore_public_acls_applies_to_unbounded_groups_but_not_named_canonical_grants`

Класс `SubjectCoverageTests`:

- `test_authenticated_group_grants_also_apply_to_configured_authenticated_user`
- `test_unsupported_principal_form_cannot_hide_additional_grants`

### `test_governance_workflow.py`

Класс `WorkflowTests`:

- `test_policy_supports_trusted_projects_acl_control_and_acl_write_permission`
- `test_registry_has_eight_unique_rules`
- `test_governance_policy_and_rules_roundtrip_in_report_and_offline_cli`

Класс `ReportTests`:

- `test_acl_control_report_status_must_match_recorded_ownership`
- `test_governance_rules_honor_accepted_exception_without_hiding_evidence`

Класс `EmptyPermissionBaselineTests`:

- `test_explicit_empty_operations_means_no_permissions_required_not_missing_baseline`

### `test_history_cli.py`

Класс `CliTests`:

- `test_import_history_filtered_export_and_comparison_between_processes`
- `test_failed_run_is_visible_and_cannot_be_compared_as_clean_report`

Класс `FailedAuditTests`:

- `test_cloud_failure_is_recorded_by_live_cli_without_a_clean_report`

### `test_package_structure.py`

Класс `PackageStructureTests`:

- `test_feature_packages_replace_generic_layers`
- `test_models_and_rules_do_not_import_external_integrations`
- `test_test_names_describe_the_subject`
- `test_every_source_module_and_definition_has_documentation`

### `test_public_access.py`

Класс `PublicAccessTests`:

- `test_bucket_read_is_listing_and_object_read_is_content_only`
- `test_bucket_write_in_vk_implies_upload_and_delete_but_object_full_control_does_not`
- `test_unconditional_deny_wins_over_acl_and_policy_allow`
- `test_unknown_conditions_and_not_elements_never_claim_safety`
- `test_ownership_enforced_disables_acl_and_authenticated_users_are_not_anonymous`
- `test_positive_anonymous_probe_is_fact_even_with_incomplete_configuration`
- `test_no_selected_object_and_unknown_policy_do_not_imply_private_files`
- `test_resource_wildcards_are_iam_not_shell_character_classes`

Класс `RuntimeEvidenceTests`:

- `test_failed_probe_does_not_become_confirmation_and_denial_does_not_resolve_unknown_policy`
- `test_public_block_ignoring_acl_does_not_ignore_policy_grants`

### `test_report_comparison.py`

Класс `ComparisonTests`:

- `test_new_persisted_and_resolved_findings`
- `test_scope_resource_policy_and_ruleset_changes_prevent_false_resolution`
- `test_missing_and_insufficient_results_never_count_as_resolved`
- `test_exception_acceptance_does_not_resolve_a_finding`
- `test_reanalysis_of_same_snapshot_does_not_prove_remediation`
- `test_runtime_confirmation_requires_matching_new_denial`

Класс `NamespaceComparisonTests`:

- `test_same_bucket_name_on_another_or_unknown_endpoint_is_not_same_resource`

Класс `ReanalysisComparisonTests`:

- `test_same_observation_cannot_be_claimed_as_new_incident`

### `test_report_formatting.py`

Класс `FormattingTests`:

- `test_filtered_view_is_explicit_and_does_not_change_original_report`
- `test_markdown_has_evidence_recommendation_time_and_escapes_cloud_content`
- `test_document_is_private_and_existing_file_is_not_overwritten`

### `test_rule_engine.py`

Класс `RuleEngineTests`:

- `test_versioning_states_evidence_risk_and_recommendation`
- `test_missing_denied_and_unsupported_are_not_passed_even_with_an_exception`
- `test_exception_preserves_finding_and_expiry_and_resource_boundaries`
- `test_context_changes_risk_and_optional_control_is_potential`
- `test_rule_registry_selection_applicability_and_determinism`
- `test_malformed_available_evidence_is_insufficient_data`

Класс `ExtensibilityTests`:

- `test_second_rule_can_use_known_absence_without_changing_engine`

### `test_s3_provider.py`

Класс `S3ProviderTests`:

- `test_configuration_requires_explicit_credentials_and_https`
- `test_lists_multiple_pages_and_connects_without_modification`
- `test_errors_are_distinct_and_never_include_sdk_messages`
- `test_cloud_audit_cannot_produce_a_demo_report`
- `test_broken_pagination_and_response_fail_instead_of_partial_success`

Класс `S3SdkWorkflowTests`:

- `test_real_sdk_response_flows_through_cli`
- `test_sdk_access_denied_is_not_an_empty_resource_list`

### `test_security_workflow.py`

Класс `PolicyTests`:

- `test_policy_parsing_and_rejection_without_leaking_values`

Класс `SecurityWorkflowTests`:

- `test_service_report_roundtrip_and_cli_offline_preserve_context_and_evidence`
- `test_insufficient_required_evidence_returns_incomplete_evaluation`

Класс `StrictPolicyTests`:

- `test_configuration_arrays_must_not_accept_objects_or_null`
- `test_saved_finding_requires_evidence_and_consistent_risk`

Класс `PolicyCliTests`:

- `test_exception_and_missing_evidence_are_preserved_through_cli_and_saved_report`

## Как менять код

Для поведения сначала пишется падающий тест, затем минимальная реализация и рефакторинг. При переносе сначала зафиксирован полный зелёный baseline, затем добавлены падающие проверки новой структуры. Смена внутреннего import-пути не должна менять CLI, результат правила или сохранённый JSON/SQLite.

Для нового правила нужны положительные/отрицательные/неполные входы, риск, доказательства и проверка через публичный сценарий. Для интеграции одного unit-теста недостаточно: используйте CLI с SDK Stubber и отдельно разрешённый реальный стенд. Фактические ограничения облачных испытаний нельзя выдавать за полное покрытие IAM.

Справочник кода обновляется после правок docstring/сигнатур. Архитектурная проверка требует docstring каждого Python-модуля и каждого именованного определения в приложении и поддерживаемых скриптах. Автоматическая проверка актуальности справочника — команда --check выше.

Результаты полного прогона и интеграции после рефакторинга: [ITERATION_10.md](ITERATION_10.md).

### `test_fixture_verification.py`

Класс `FixtureVerificationTests`:

- `test_partial_publication_retries_without_losing_attempt_evidence`
- `test_closure_retries_until_new_unsigned_requests_deny_access`
- `test_exhausted_attempts_fail_and_cleanup_is_still_attempted`

Общий helper `stage` создаёт искусственную пару снимок/отчёт; `run_fixture` подменяет только облачные зависимости и sleep, исполняет реальный main стендового скрипта и проверяет его сводку/уборку. Паузы не замедляют тесты, живого облака здесь нет.

## Дополнение: итерация 11

Запуск только нового набора: `PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -p 'test_staged_*.py' -v`. Выполнены 33 новых метода и четыре затронутые структурные проверки. Полный набор после итерации 10 не перезапускался; 167 — число объявленных методов, а не результат нового полного прогона. Интеграция на трёх искусственных бакетах и ограничения — [ITERATION_11.md](ITERATION_11.md).

### `test_staged_scan.py`

Класс `StagedScanTests`:

- `test_explicit_targets_do_not_require_listing_permission_and_continue_on_error`
- `test_internal_stage_runs_even_when_external_listing_is_denied`
- `test_all_buckets_requires_credentials_and_listing_failure_is_saved`
- `test_targets_are_strict_per_bucket_and_duplicates_rejected`
- `test_all_buckets_mutations_only_apply_to_explicit_permission_names`
- `test_fresh_combined_snapshot_keeps_external_facts_for_offline_audit`
- `test_recovered_get_evidence_is_not_lost_after_an_external_stage_error`
- `test_common_policy_applies_to_discovered_buckets_too`

### `test_staged_probes.py`

Класс `DiscoveryTests`:

- `test_pages_stop_at_limit_and_report_unseen_objects`
- `test_denial_is_not_an_empty_successful_listing_and_broken_tokens_stop`

Класс `ExternalInspectorTests`:

- `test_known_object_get_runs_even_when_list_denied_and_no_mutation_opt_in`

Класс `MutationEvidenceTests`:

- `test_delete_204_without_observed_absence_is_unverified`
- `test_preexisting_key_is_never_modified`
- `test_unsigned_only_requires_residue_acceptance`
- `test_write_denial_does_not_imply_delete_denial`
- `test_object_lock_unknown_prevents_mutations`
- `test_cleanup_never_removes_foreign_version_or_other_key`
- `test_preparation_network_failure_still_searches_for_residual_versions`
- `test_unsigned_upload_reports_residue_even_if_unsigned_cleanup_returns_success`
- `test_cleanup_marker_header_names_are_case_insensitive`
- `test_unversioned_cleanup_uses_current_object_not_get_object_version_permission`

Класс `DiscoveryLimitTests`:

- `test_server_returning_more_than_requested_is_not_a_complete_scope`

Класс `MutationReadinessTests`:

- `test_versioning_failure_cannot_be_mistaken_for_absent_object_lock`

### `test_staged_cli.py`

Класс `ScanConfigurationTests`:

- `test_no_keys_is_explicit_unsigned_mode_but_partial_keys_are_invalid`

Класс `ScanStorageTests`:

- `test_roundtrip_is_private_immutable_and_rejects_corruption`

Класс `ScanCliTests`:

- `test_unsigned_cli_never_constructs_signed_provider_and_reads_offline_report`
- `test_all_buckets_without_credentials_and_unknown_mutation_scope_fail_before_io`
- `test_two_real_service_pipelines_save_reports_and_offline_replay_keeps_unsigned_facts`
- `test_stored_summary_rejects_forged_findings_and_version`
- `test_unsigned_factory_never_uses_environment_credentials`

### `test_staged_fixture.py`

Класс `StagedFixtureTests`:

- `test_cleanup_continues_after_a_bucket_error_and_removes_versions`
- `test_no_owned_buckets_means_no_cloud_cleanup_requests`
- `test_public_evidence_may_come_from_separate_runs_but_requires_clean_verified_mutations`

## Удобный локальный запуск

После итерации 11 добавлено семь новых тестов test_local_environment.py: загрузка/приоритет без изменения os.environ, кавычки/комментарии/неисполнение shell, ошибки/лимит/редакция секретов, CLI default/explicit/disabled .env, help/version, установленная консольная команда и корневой launcher без PYTHONPATH. Установка pip install -e . проверена в локальной .venv. Два installed-теста пропускаются, если пакет в тестовом интерпретаторе ещё не установлен; в рабочей проверке прошли все семь без пропусков. Повторно проверены затронутые staged-, bootstrap- и структурные тесты; полного нового прогона всех 174 методов не было.

Класс `LocalEnvironmentTests`:

- `test_optional_file_and_process_environment_take_precedence_without_mutation`
- `test_quotes_comments_and_shell_expressions_are_literal`
- `test_invalid_or_oversized_file_never_exposes_values`

Класс `LocalEnvironmentCliTests`:

- `test_check_loads_current_directory_file_and_explicit_file`
- `test_help_and_version_ignore_invalid_dotenv_and_missing_explicit_file_is_controlled`

Класс `InstalledCommandTests`:

- `test_installed_command_runs_without_pythonpath`
- `test_project_launcher_runs_without_activation`

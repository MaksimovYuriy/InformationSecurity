"""Запуск через python -m cloud_audit: передаёт управление CLI и возвращает его код завершения."""
from cloud_audit.cli import main

raise SystemExit(main())

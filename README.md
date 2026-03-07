# secret-scanner

Стартовый Python-проект для поиска секретов в коде с фокусом на локальную разработку и CI.

Что уже есть:
- CLI на `typer`
- конфиг через `.secret-scanner.toml`
- collectors:
  - `filesystem`
  - `git staged`
  - `git diff`
- базовые модели (`SourceFragment`, `Candidate`, `Finding`, `ScanResult`)
- built-in detectors:
  - `private_key`
  - `generic_assignment`
- built-in filters:
  - `path_filter`
  - `dummy_value_filter`
  - `baseline_filter`
- baseline create/update/use
- text/json reporter

## Установка

```bash
pip install -e .
```

## Быстрый запуск

```bash
secret-scan scan .
secret-scan scan . --format json
secret-scan scan --staged
secret-scan scan --git-diff origin/main..HEAD
secret-scan baseline create .
secret-scan baseline update --staged
```

## Пример конфига

Смотри файл `.secret-scanner.toml`.

## Что делать дальше

Ближайшие логичные шаги:
- добавить `jwt` и `uri_credentials` detectors
- добавить entropy/context filters
- добавить `sarif` reporter
- сделать `git history` collector
- добавить validation subsystem

# secret-scanner

Стартовый Python-проект для поиска секретов в коде с фокусом на локальную разработку, pre-commit и CI.

## Что уже есть

- CLI на `typer`
- конфиг через `.secret-scanner.toml`
- collectors:
  - `filesystem`
  - `git staged`
  - `git diff`
- built-in detectors:
  - `private_key`
  - `generic_assignment`
  - `jwt`
  - `uri_credentials`
- built-in filters:
  - `path_filter`
  - `dummy_value_filter`
  - `inline_ignore_filter`
  - `test_context_filter`
  - `baseline_filter`
- baseline create/update/use
- reporters:
  - `text`
  - `json`
  - `sarif`

## Установка

```bash
pip install -e .
```

## Быстрый запуск

```bash
secret-scan scan .
secret-scan scan . --format json
secret-scan scan . --format sarif
secret-scan scan --staged
secret-scan scan --git-diff origin/main..HEAD
secret-scan baseline create .
secret-scan baseline update --staged
```

## Примеры

### Проверить локальную папку

```bash
secret-scan scan testdata
```

### Проверить staged-изменения

```bash
git add .
secret-scan scan --staged
```

### Сгенерировать SARIF для CI

```bash
secret-scan scan . --format sarif > results.sarif
```

## Inline ignore

Если строку нужно сознательно пропустить, можно добавить маркер:

```python
API_KEY = "example"  # secret-scan: ignore
```

## Что проверяется сейчас

### `private_key`
Ловит PEM/OpenSSH private key блоки.

### `generic_assignment`
Ловит присваивания вроде:

```python
password = "super-secret"
api_key = "sk_live_..."
client_secret: "abc123"
```

### `jwt`
Ловит JWT только если первые два сегмента декодируются как валидный JSON.

### `uri_credentials`
Ловит URI с embedded credentials:

```text
postgres://alice:s3cr3t@db.internal/app
https://user:pass@example.com/api
```

## Тесты

```bash
pytest
```

Сейчас покрыты:
- baseline suppression
- staged scan
- git diff scan
- jwt / uri detectors
- inline ignore / test context suppression
- sarif reporter

## Ближайшие логичные шаги

- добавить `CliRunner`-тесты для CLI
- добавить `git history` collector
- усилить `generic_assignment` через entropy/context scoring
- добавить provider-specific detectors
- добавить validation subsystem как opt-in режим

# secret-scan

Утилита для поиска секретов в коде и конфигурационных файлах.

Сейчас `secret-scan` умеет находить:

- приватные ключи (`PRIVATE KEY`, `OPENSSH PRIVATE KEY`);
- секреты в присваиваниях вроде `password = "..."`, `api_key: "..."`;
- JWT-токены;
- URI со встроенными логином и паролем, например `postgres://user:pass@host/db`.

Утилита подходит для:

- локальной проверки папки с кодом;
- проверки только staged-изменений перед коммитом;
- проверки diff между двумя git-ревизиями;
- использования в CI.

---

## Установка

Открой терминал в корне проекта.

### Если у тебя fish shell

```fish
python -m venv .venv
source .venv/bin/activate.fish
pip install -e .
```

### Если bash или zsh

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Проверить, что всё установилось:

```bash
secret-scan --help
```

Если команда не находится, запускай так:

```bash
python -m secret_scanner.cli --help
```

---

## Быстрый старт

### Проверить текущую папку

```bash
secret-scan scan .
```

### Проверить конкретную папку

```bash
secret-scan scan testdata
```

### Получить результат в JSON

```bash
secret-scan scan . --format json
```

### Получить результат в SARIF

```bash
secret-scan scan . --format sarif
```

SARIF удобен для CI и систем code scanning.

---

## Подготовка тестовых файлов

Создай папку для примеров:

```bash
mkdir -p testdata
```

Создай файл `testdata/app.py`:

```python
API_KEY = "sk_live_very_secret_value_12345"
PASSWORD = "dummy"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.signature"
DB_URL = "postgres://alice:s3cr3t@db.internal/app"
```

Запусти сканирование:

```bash
secret-scan scan testdata
```

Ожидаемое поведение:

- `API_KEY` будет найден;
- `JWT_TOKEN` будет найден;
- `DB_URL` будет найден;
- `PASSWORD = "dummy"` скорее всего будет проигнорирован как тестовое значение.

---

## Режимы работы

### Обычное сканирование файлов

Проверяет файлы и папки на диске:

```bash
secret-scan scan .
secret-scan scan src tests
```

### Проверка staged-изменений

Проверяет содержимое, уже добавленное через `git add`:

```bash
secret-scan scan --staged
```

Это удобно перед коммитом.

### Проверка diff между ревизиями

Проверяет изменённые файлы между двумя git-ссылками:

```bash
secret-scan scan --git-diff HEAD~1..HEAD
secret-scan scan --git-diff origin/main..HEAD
```

Это удобно для CI и pull request-проверок.

---

## Baseline

Baseline нужен, чтобы зафиксировать уже известные старые находки и не получать их снова при каждом запуске.

### Создать baseline

```bash
secret-scan baseline create .
```

После этого появится файл:

```text
.secrets.baseline.json
```

### Обновить baseline

```bash
secret-scan baseline update .
```

### Запускать сканирование с baseline

Обычная команда `scan` сама использует baseline, если он есть:

```bash
secret-scan scan .
```

### Игнорировать baseline для одного запуска

```bash
secret-scan scan . --no-baseline
```

Это полезно, если нужно увидеть вообще все находки.

---

## Игнорирование отдельной строки

Если строку нужно пропустить сознательно, добавь комментарий:

```python
API_KEY = "example"  # secret-scan: ignore
```

После этого строка не будет попадать в отчёт.

---

## Форматы вывода

### Текстовый вывод

По умолчанию:

```bash
secret-scan scan .
```

Подходит для локальной работы.

### JSON

```bash
secret-scan scan . --format json
```

Подходит для автоматической обработки и интеграций.

### SARIF

```bash
secret-scan scan . --format sarif > results.sarif
```

Подходит для GitHub Code Scanning и похожих систем.

---

## Коды завершения

Это важно для CI.

Утилита завершает работу с кодом:

- `0` — блокирующих находок нет;
- `1` — найдены секреты уровня, который считается блокирующим;
- `2` — ошибка использования, например неправильные параметры;
- `3` — внутренняя ошибка выполнения.

По умолчанию блокирующие уровни берутся из конфига:

```toml
[severity]
fail_on = ["high", "critical"]
```

---

## Конфигурация

Файл конфигурации называется:

```text
.secret-scanner.toml
```

Пример:

```toml
[scan]
max_file_size_kb = 512
follow_symlinks = false
workers = 4

[output]
format = "text"
show_snippet = true
mask_secrets = true

[severity]
fail_on = ["high", "critical"]

[baseline]
path = ".secrets.baseline.json"
use_baseline = true

[filters]
ignore_paths = [
  "node_modules/**",
  "dist/**",
  "build/**",
  ".venv/**",
  "vendor/**"
]
dummy_values = [
  "test",
  "dummy",
  "example",
  "changeme",
  "your_api_key_here",
  "xxx"
]
suppress_test_paths = true
inline_ignore_markers = ["secret-scan: ignore"]

[detectors]
enabled = [
  "private_key",
  "generic_assignment",
  "jwt",
  "uri_credentials"
]
```

### Запуск с явным конфигом

```bash
secret-scan scan . --config .secret-scanner.toml
```

---

## Типовой сценарий использования

### Локальная проверка

```bash
secret-scan scan .
```

### Перед коммитом

```bash
git add .
secret-scan scan --staged
```

### В CI

```bash
secret-scan scan --git-diff origin/main..HEAD --format sarif > results.sarif
```

### Для старого репозитория

Сначала зафиксировать текущие известные находки:

```bash
secret-scan baseline create .
```

Потом запускать обычную проверку:

```bash
secret-scan scan .
```

---

## Что делать, если команда не запускается

### Команда `secret-scan` не найдена

Запусти так:

```bash
python -m secret_scanner.cli scan .
```

### Ошибка активации `.venv/bin/activate`

Если у тебя fish shell, используй:

```fish
source .venv/bin/activate.fish
```

### Ничего не находится, хотя секрет есть

Проверь:

- не попадает ли файл под `ignore_paths`;
- не добавлен ли inline ignore;
- не скрывает ли находку baseline;
- не является ли значение dummy-типа (`example`, `dummy`, `changeme`).

Для проверки без baseline:

```bash
secret-scan scan . --no-baseline
```

---

## Что уже умеет и чего пока нет

### Уже умеет

- scan по файлам и папкам;
- `--staged`;
- `--git-diff`;
- baseline create/update/use;
- text/json/sarif output;
- inline ignore;
- подавление шума в `tests`, `examples`, `docs`.

### Пока не умеет

- сканирование всей git history;
- online validation токенов;
- большое число provider-specific детекторов;
- продвинутый entropy scoring;
- глубокий semantic analysis.

---

## Минимальный набор команд на каждый день

```bash
secret-scan scan .
secret-scan scan --staged
secret-scan baseline create .
secret-scan scan . --no-baseline
secret-scan scan . --format sarif
```

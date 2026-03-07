from __future__ import annotations

import json
from pathlib import Path

from secret_scanner.config.models import AppConfig
from secret_scanner.engine.factory import build_scanner
from secret_scanner.reporters import SarifReporter


def test_jwt_and_uri_detectors_find_expected_values(tmp_path: Path) -> None:
    content = """\
API_URL = \"postgres://alice:s3cr3tpass@db.internal/app\"\nJWT = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoiQW5kcmV5In0.c2lnbmF0dXJlMTIz\"\n"""
    target = tmp_path / "app.py"
    target.write_text(content, encoding="utf-8")

    scanner = build_scanner([str(tmp_path)], AppConfig(), use_baseline=False)
    result = scanner.run()
    detector_ids = {finding.detector_id for finding in result.findings}

    assert "uri_credentials" in detector_ids
    assert "jwt" in detector_ids


def test_inline_ignore_and_test_context_filters_suppress_noise(tmp_path: Path) -> None:
    example_dir = tmp_path / "examples"
    example_dir.mkdir()
    (example_dir / "app.py").write_text(
        'API_KEY = "real-looking-secret"  # secret-scan: ignore\n',
        encoding="utf-8",
    )

    scanner = build_scanner([str(tmp_path)], AppConfig(), use_baseline=False)
    result = scanner.run()

    assert result.findings == []


def test_sarif_reporter_outputs_valid_structure(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text('token = "postgres://alice:s3cr3tpass@db.internal/app"\n', encoding="utf-8")

    scanner = build_scanner([str(tmp_path)], AppConfig(), use_baseline=False)
    result = scanner.run()
    sarif = json.loads(SarifReporter().render(result))

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "secret-scanner"
    assert run["results"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("app.py")
def test_generic_assignment_does_not_flag_regular_non_secret_assignments(tmp_path: Path) -> None:
    target = tmp_path / "settings.py"
    target.write_text('PORT = 8080\nTIMEOUT = 30\nDEBUG = true\n', encoding="utf-8")

    scanner = build_scanner([str(tmp_path)], AppConfig(), use_baseline=False)
    result = scanner.run()

    assert result.findings == []


def test_generic_assignment_dummy_value_is_suppressed(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text('TOKEN = "dummy"\n', encoding="utf-8")

    scanner = build_scanner([str(tmp_path)], AppConfig(), use_baseline=False)
    result = scanner.run()

    assert result.findings == []

def test_uri_credentials_ignores_too_short_passwords(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text('DB_URL = "postgres://alice:abc@db.internal/app"\n', encoding="utf-8")

    scanner = build_scanner([str(tmp_path)], AppConfig(), use_baseline=False)
    result = scanner.run()

    assert all(f.detector_id != "uri_credentials" for f in result.findings)


def test_uri_credentials_still_detects_reasonable_passwords(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text('DB_URL = "postgres://alice:s3cr3t9@db.internal/app"\n', encoding="utf-8")
    scanner = build_scanner([str(tmp_path)], AppConfig(), use_baseline=False)
    result = scanner.run()

    assert any(f.detector_id == "uri_credentials" for f in result.findings)

def test_generic_assignment_ignores_placeholders(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text('API_KEY = "your_example_token_here"\n', encoding="utf-8")

    scanner = build_scanner([str(tmp_path)], AppConfig(), use_baseline=False)
    result = scanner.run()

    assert all(f.detector_id != "generic_assignment" for f in result.findings)


def test_generic_assignment_detects_high_entropy_secret(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text('API_KEY = "Ab9_Xz2mQ7pLk3vT"\n', encoding="utf-8")

    scanner = build_scanner([str(tmp_path)], AppConfig(), use_baseline=False)
    result = scanner.run()

    assert any(f.detector_id == "generic_assignment" for f in result.findings)


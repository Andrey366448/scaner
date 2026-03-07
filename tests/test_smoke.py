from secret_scanner.config.models import AppConfig
from secret_scanner.engine.factory import build_scanner


def test_scanner_runs_on_empty_tmpdir(tmp_path):
    scanner = build_scanner([str(tmp_path)], AppConfig())
    result = scanner.run()
    assert result.findings == []

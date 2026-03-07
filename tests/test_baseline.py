from secret_scanner.baseline import BaselineStore
from secret_scanner.config.models import AppConfig
from secret_scanner.engine.factory import build_scanner


def test_baseline_suppresses_existing_findings(tmp_path):
    secret_file = tmp_path / "app.py"
    secret_file.write_text('API_KEY = "sk_live_super_secret_value"\n', encoding="utf-8")

    config = AppConfig()
    config.baseline.path = str(tmp_path / ".secrets.baseline.json")

    initial_result = build_scanner([str(tmp_path)], config, use_baseline=False).run()
    assert len(initial_result.findings) == 1

    BaselineStore(config.baseline.path).write_findings(initial_result.findings)

    suppressed_result = build_scanner([str(tmp_path)], config, use_baseline=True).run()
    assert suppressed_result.findings == []

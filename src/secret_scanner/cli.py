from __future__ import annotations

import typer

from secret_scanner.baseline import BaselineStore
from secret_scanner.config import load_config
from secret_scanner.engine.factory import build_scanner
from secret_scanner.exit_codes import ExitCodes
from secret_scanner.models import Severity
from secret_scanner.reporters import JsonReporter, SarifReporter, TextReporter

app = typer.Typer(help="Developer-first secret scanner")
baseline_app = typer.Typer(help="Manage baseline files")
app.add_typer(baseline_app, name="baseline")


@app.command()
def scan(
    paths: list[str] = typer.Argument(None, help="Files or directories to scan."),
    config: str | None = typer.Option(None, "--config", help="Path to TOML config."),
    format: str | None = typer.Option(None, "--format", help="Output format: text, json or sarif."),
    staged: bool = typer.Option(False, "--staged", help="Scan staged content from git index."),
    git_diff: str | None = typer.Option(None, "--git-diff", help="Scan changed files from a git refspec, e.g. origin/main..HEAD."),
    no_baseline: bool = typer.Option(False, "--no-baseline", help="Ignore baseline suppression for this run."),
) -> None:
    """Scan one or more paths for hardcoded secrets."""
    try:
        if staged and git_diff is not None:
            raise typer.BadParameter("Use either --staged or --git-diff, not both.")

        app_config = load_config(config)
        if format is not None:
            app_config.output.format = format

        scanner = build_scanner(
            paths or ["."],
            app_config,
            staged=staged,
            git_diff=git_diff,
            use_baseline=not no_baseline,
        )
        result = scanner.run()
        _render_result(result, app_config.output.format)

        fail_on = {Severity(level) for level in app_config.severity.fail_on}
        has_blocking_findings = any(finding.severity in fail_on for finding in result.findings)
        raise typer.Exit(code=ExitCodes.FINDINGS if has_blocking_findings else ExitCodes.OK)
    except typer.Exit:
        raise
    except FileNotFoundError as exc:
        typer.echo(f"Config error: {exc}", err=True)
        raise typer.Exit(code=ExitCodes.USAGE_ERROR)
    except typer.BadParameter as exc:
        typer.echo(f"Usage error: {exc}", err=True)
        raise typer.Exit(code=ExitCodes.USAGE_ERROR)
    except Exception as exc:  # pragma: no cover - last-resort guard for CLI
        typer.echo(f"Runtime error: {exc}", err=True)
        raise typer.Exit(code=ExitCodes.RUNTIME_ERROR)


@baseline_app.command("create")
def baseline_create(
    paths: list[str] = typer.Argument(None, help="Files or directories to scan."),
    config: str | None = typer.Option(None, "--config", help="Path to TOML config."),
    staged: bool = typer.Option(False, "--staged", help="Build baseline from staged content."),
    git_diff: str | None = typer.Option(None, "--git-diff", help="Build baseline from a git refspec."),
) -> None:
    """Create a baseline file from current findings."""
    _write_baseline(paths=paths or ["."], config_path=config, staged=staged, git_diff=git_diff)


@baseline_app.command("update")
def baseline_update(
    paths: list[str] = typer.Argument(None, help="Files or directories to scan."),
    config: str | None = typer.Option(None, "--config", help="Path to TOML config."),
    staged: bool = typer.Option(False, "--staged", help="Refresh baseline from staged content."),
    git_diff: str | None = typer.Option(None, "--git-diff", help="Refresh baseline from a git refspec."),
) -> None:
    """Update an existing baseline file with current findings."""
    _write_baseline(paths=paths or ["."], config_path=config, staged=staged, git_diff=git_diff)



def _write_baseline(paths: list[str], config_path: str | None, staged: bool, git_diff: str | None) -> None:
    try:
        if staged and git_diff is not None:
            raise typer.BadParameter("Use either --staged or --git-diff, not both.")

        app_config = load_config(config_path)
        scanner = build_scanner(
            paths,
            app_config,
            staged=staged,
            git_diff=git_diff,
            use_baseline=False,
        )
        result = scanner.run()
        store = BaselineStore(app_config.baseline.path)
        store.write_findings(result.findings)
        typer.echo(f"Baseline written to {store.path} ({len(result.findings)} findings).")
        raise typer.Exit(code=ExitCodes.OK)
    except typer.Exit:
        raise
    except FileNotFoundError as exc:
        typer.echo(f"Config error: {exc}", err=True)
        raise typer.Exit(code=ExitCodes.USAGE_ERROR)
    except typer.BadParameter as exc:
        typer.echo(f"Usage error: {exc}", err=True)
        raise typer.Exit(code=ExitCodes.USAGE_ERROR)
    except Exception as exc:  # pragma: no cover - last-resort guard for CLI
        typer.echo(f"Runtime error: {exc}", err=True)
        raise typer.Exit(code=ExitCodes.RUNTIME_ERROR)



def _render_result(result, output_format: str) -> None:
    if output_format == "json":
        typer.echo(JsonReporter().render(result))
    elif output_format == "sarif":
        typer.echo(SarifReporter().render(result))
    else:
        typer.echo(TextReporter().render(result))


if __name__ == "__main__":
    app()

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

# Silence Node.js version warning from cdk8s/jsii (Find it annoying; no effect on functionality)
os.environ.setdefault("JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION", "1")

import typer

from kalm_benchmark import benchmark
from kalm_benchmark.evaluation import evaluation
from kalm_benchmark.evaluation.scanner_manager import SCANNERS, ScannerBase
from kalm_benchmark.evaluation.scanner_service import EvaluationService
from kalm_benchmark.manifest_generator.gen_manifests import create_manifests
from kalm_benchmark.utils.config import get_config
from kalm_benchmark.utils.constants import UpdateType
from kalm_benchmark.utils.exceptions import DatabaseError, ScannerNotFoundError

app = typer.Typer(name="kalm-benchmark", no_args_is_help=True)


@app.command("generate")
def generate_manifests(
    out_dir: Path = typer.Option(
        "manifests", "--out", "-o", help="The output folder of the generated manifests. Defaults to 'manifests'"
    ),
    file_per_check: bool = typer.Option(
        True,
        "--file-per-check/--single-file",
        help=(
            "Flag dictating if a dedicated file will be generated per check. "
            "If false, only a file called 'app.yaml` with all checks will be generated."
        ),
    ),
    overview: bool = typer.Option(
        False,
        help=(
            "If the flag is set only an overview of checks in the benchmark is created and exported as markdown table."
        ),
    ),
    overview_format: evaluation.OverviewType = typer.Option(
        evaluation.OverviewType.Markdown,
        help="The output format of the generated overview printed to StdOut. "
        "`out` argument will be ignored. Only relevant when `overview` flag is set",
    ),
) -> None:
    """
    Generate a pre-configured set of manifests and place them in the specified folder.
    """

    if overview:
        if overview_format == evaluation.OverviewType.Markdown:
            misclassified_checks = evaluation.create_benchmark_overview(out_dir, format=overview_format)
            if len(misclassified_checks) > 0:
                typer.secho("Misclassified checks: " + ", ".join(misclassified_checks), fg=typer.colors.RED)
        elif overview_format == evaluation.OverviewType.Latex:
            tbl = evaluation.create_benchmark_overview_latex_table()
            typer.echo(tbl)
    else:
        num_checks = create_manifests(str(out_dir), file_per_check=file_per_check)
        if num_checks > 0:
            if file_per_check:
                typer.echo(f"Successfully created {num_checks} files in folder {out_dir}")
            else:
                res_path = out_dir / "app.yaml"
                typer.echo(f"Wrote the manifests for all {num_checks} to file '{res_path}'")
        else:
            typer.echo("No files created :(")


@app.command()
def evaluate(
    tool: str = typer.Argument(default=None),
    scan_run_id: str = typer.Option(
        None,
        "--run-id",
        help="Specific scan run ID to evaluate. If not provided, uses latest scan.",
    ),
) -> None:
    """
    Evaluate the results of one or more scanners from the database.
    :param tool: the name of the scanner.
    :param scan_run_id: optional specific scan run to evaluate
    """
    if tool is None:
        typer.echo("Evaluation of all tools is not yet supported")
        raise typer.Exit(1)

    # Note: handling of the scanner selection can lead to the process being aborted
    scanner = _handle_scanner_selection(tool)

    try:
        service = EvaluationService()

        results = service.load_scanner_results(scanner.NAME.lower(), scan_run_id)

        if not results:
            typer.echo(f"No results found for {scanner.NAME}")
            raise typer.Exit(1)

        df = evaluation.evaluate_scanner(scanner, results)
        summary = evaluation.create_summary(df)
        scan_runs = service.db.get_scan_runs(scanner_name=scanner.NAME.lower())
        if scan_runs:
            latest_scan = scan_runs[0]
            service.db.save_evaluation_summary(
                scanner_name=scanner.NAME.lower(),
                summary=summary,
                scan_timestamp=latest_scan["timestamp"],
                scanner_version=summary.version,
            )
            typer.echo("Saved evaluation summary to database")

        typer.echo(f"Here are the results of the evaluation of {tool}: ")
        typer.echo(f"Scanner: {scanner.NAME}")
        typer.echo(f"Version: {summary.version or 'Unknown'}")
        typer.echo(f"Score: {summary.score: .3f}")
        typer.echo(f"Coverage: {summary.coverage: .3f}")
        typer.echo(f"Extra checks: {summary.extra_checks}")
        typer.echo(f"Missing checks: {summary.missing_checks}")

        if summary.ccss_alignment_score:
            typer.echo(f"CCSS Alignment: {summary.ccss_alignment_score: .3f}")

    except Exception as e:
        typer.echo(f"Evaluation failed: {e}")
        raise typer.Exit(1)


@app.command()
def scan(
    tool: str,
    kubecontext: Optional[bool] = typer.Option(
        None, "--ctx", "-c", is_flag=True, help=("Flag, if set the current kube-context will be used")
    ),
    files: Path = typer.Option(
        None,
        "--files",
        "-f",
        exists=True,
        file_okay=True,
        dir_okay=True,
        resolve_path=False,
        help=(
            "The path to the manifest(s) which will be scanned. "
            + " This can be either a specific file or a directory."
        ),
    ),
    out: Optional[Path] = typer.Option(
        None,
        "--out",
        "-o",
        file_okay=True,
        dir_okay=True,
        writable=True,
        help=(
            "The path where the resulting output will be written to. "
            + "If the path points to a directory, the resulting file will be named after the scanner."
        ),
    ),
) -> None:
    """Run a scan with the specified tool.

    :param tool: the tool which will be used for the scan
    :param kubecontext: if the flag is set, a cluster scan will performed against the cluster specified in
        the active kube-context. This is mutually-exclusive with the `-f` argument.
    :param files: a path to the target folder or file. If specified a manifest scan will be performed.
        This is mutually-exclusive with the `-c` argument.
    :param out: if set, the results of the scan will be stored in the specified folder.
    """
    scanner = _handle_scanner_selection(tool)

    gen = benchmark.scan(scanner, context=kubecontext, target_path=files)

    had_error = False
    had_exit_code = False
    try:
        # note: `for .. in` swallows `StopIteration` thus next() has to be called explicitely
        while update := next(gen):
            show_scan_update(*update)
            if update[0] == UpdateType.Error:
                had_error = True
            if "exit-code:" in update[1]:
                had_exit_code = True
    except StopIteration as st:
        results = st.value

    if results is None:
        typer.secho("Scan yield no results!", color=typer.colors.BRIGHT_YELLOW)
        return

    if len(results) > 0:
        typer.echo("Scan concluded successfully with results.")

    if had_exit_code:
        show_scan_update(
            UpdateType.Info,
            "Note: some tools treat flaws above a threshold as error. This does not mean the scan failed!",
        )

    if had_error:
        typer.echo("No results were saved due to an error when starting the scan!")
        return

    # Save to unified database only
    try:
        unified_service = EvaluationService()

        # Create a descriptive source identifier
        source_identifier = None
        if out is not None and out.is_dir():
            version = scanner.get_version() or "unknown"
            date = datetime.now().strftime("%Y-%m-%d")
            source_identifier = f"{scanner.NAME.lower()}_v{version}_{date}"
        elif out is not None:
            source_identifier = str(out)

        scan_run_id = unified_service.save_scanner_results(
            scanner_name=scanner.NAME.lower(),
            results=results,
            scanner_version=scanner.get_version(),
            source_file=source_identifier,
        )
        typer.echo(f"Successfully saved {len(results)} results to database (run: {scan_run_id})")
    except Exception as e:
        typer.echo(f"Failed to save results to database: {e}")
        raise typer.Exit(1)


def show_scan_update(level: benchmark.UpdateType, message: str) -> None:
    """Print scan updates colorized depending on the level
    :param level: the level of the message
    :param message: the text to show in the terminal
    """
    match level:
        case benchmark.UpdateType.Warning:
            color = typer.colors.BRIGHT_YELLOW
        case benchmark.UpdateType.Error:
            color = typer.colors.RED
        case _:
            color = typer.colors.RESET

    typer.secho(message, fg=color)


def _handle_scanner_selection(tool: str) -> ScannerBase:
    """Generic handling of the scanner with the given name.
    If the provided name does not match any registered tool the user is offered
    one or more suggestions.
    If there is one close match the user is asked to confirm if the suggestion should be used instead.
    For more choices, the user may pick the appropriate one or choices, the user may pick the appropriate
    one or cancel the selection process.

    :param tool: the name of the tool
    :raises typer.Exit: exit with code=1 if no valid scanner can be selected
    :return: a scanner instance
    """
    if tool in SCANNERS.keys():
        return SCANNERS.get(tool)

    # fallback suggest alternative scanners
    alternatives = SCANNERS.closest_matches(tool)
    msg = f"No scanner '{tool}' found! "
    choice = None

    if len(alternatives) == 1:
        suggestion = alternatives[0]
        # if it's just a difference in the casing, then pick the only alternative
        if suggestion.lower() == tool.lower():
            choice = suggestion
        else:
            res = typer.confirm(f"{msg}Perhaps you meant '{suggestion}'?", default=True)
            choice = suggestion if res else None
    elif len(alternatives) > 1:
        suggestion = ", ".join([f"({i}) {name}" for i, name in enumerate(alternatives, start=1)])
        typer.echo(f"{msg}Perhaps you meant on of: {suggestion}?")

        msg = "Please select the corresponding number or 0 to cancel."
        while (res := typer.prompt(msg, 1, type=int)) > len(alternatives):
            typer.secho(f"{res} is not a valid choice!", fg=typer.colors.RED)
        choice = alternatives[res - 1] if res > 0 else None

    if choice is None:
        typer.secho(f"Aborting because '{tool}' is not a valid tool!", fg=typer.colors.RED)
        raise typer.Exit(1)

    selected_scanner = SCANNERS.get(choice)
    if selected_scanner is None:
        raise ScannerNotFoundError(f"Scanner '{choice}' not found in registry")

    return selected_scanner


@app.command()
def serve() -> None:
    """
    Start a web-ui which from where the scan and evaluation results can be managed.
    """
    import sys

    from streamlit.web import cli as streamlitcli

    curr_file = Path(sys.modules[__name__].__file__)
    app_file = curr_file.parent / "ui/app.py"
    sys.argv = [
        "streamlit",
        "run",
        str(app_file),
    ]
    sys.exit(streamlitcli.main())


@app.command("config")
def show_config() -> None:
    """
    Show current configuration settings.
    """
    config = get_config()

    typer.echo("=" * 50)
    typer.echo("KALM Configuration")
    typer.echo("=" * 50)
    typer.echo(f"Database Path: {config.database_path}")
    typer.echo(f"Log Level: {config.log_level}")
    typer.echo(f"UI Host: {config.ui_host}")
    typer.echo(f"UI Port: {config.ui_port}")
    typer.echo(f"Scan Timeout: {config.scan_timeout}s")
    typer.echo(f"Data Directory: {config.data_directory}")
    typer.echo(f"Manifest Directory: {config.manifest_directory}")
    typer.echo(f"Log Directory: {config.log_directory}")
    typer.echo(f"Max Results Cache: {config.max_results_cache}")
    typer.echo(f"Cleanup Keep Runs: {config.cleanup_keep_runs}")
    typer.echo("=" * 50)
    typer.echo("\n💡 Set environment variables to customize:")
    typer.echo("  KALM_DB_PATH, KALM_LOG_LEVEL, KALM_UI_HOST, KALM_UI_PORT")
    typer.echo("  KALM_SCAN_TIMEOUT, KALM_DATA_DIR, KALM_MANIFEST_DIR, etc.")


@app.command("db-stats")
def show_database_stats(
    db_path: Path = typer.Option("./data/kalm.db", "--db-path", help="Path to the database"),
) -> None:
    """
    Show database statistics and information.
    """
    if not db_path.exists():
        typer.echo(f"Database not found at {db_path}")
        raise typer.Exit(1)

    try:
        service = EvaluationService(str(db_path))
        stats = service.get_database_stats()

        typer.echo("=" * 50)
        typer.echo("KALM Database Statistics")
        typer.echo("=" * 50)
        typer.echo(f"Total scanner results: {stats['total_scanner_results']}")
        typer.echo(f"Total scan runs: {stats['total_scan_runs']}")
        typer.echo(f"Total evaluation summaries: {stats['total_evaluation_summaries']}")
        typer.echo(f"Unique scanners: {stats['unique_scanners']}")

        if stats["recent_activity"]:
            typer.echo("\nRecent scanner activity:")
            for activity in stats["recent_activity"]:
                typer.echo(f" - {activity['scanner']}: {activity['last_activity']}")

        typer.echo("=" * 50)

    except DatabaseError as e:
        typer.echo(f"Database error: {e}")
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"Failed to get database stats: {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()

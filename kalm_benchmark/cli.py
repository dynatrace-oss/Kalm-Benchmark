import os
from datetime import datetime
from pathlib import Path
from typing import Optional

# Silence Node.js version warning from cdk8s/jsii (Find it annoying; no effect on functionality)
os.environ.setdefault("JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION", "1")

import typer

from kalm_benchmark import benchmark
from kalm_benchmark.constants import UpdateType
from kalm_benchmark.evaluation import evaluation
from kalm_benchmark.evaluation.scanner_manager import SCANNERS, ScannerBase
from kalm_benchmark.manifest_generator.gen_manifests import create_manifests
from kalm_benchmark.ui.utils import get_version_from_result_file

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
        help="The output format of the generated overview printed to StdOut. `out` argument will be ignored. Only relevant when `overview` flag is set",
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
            tbl = evaluation.create_benchark_overview_latex_table()
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
    file: Path = typer.Option(
        None,
        "-f",
        file_okay=True,
        dir_okay=False,
        help="The path to a file with the results of the scan performed by the tool, which will be evaluated",
    ),
) -> None:
    """
    Evaluate the results of one or more scanners.
    :param tool: the name of the scanner.
    :param file: optional path to the results of the scanner. If no path is provided,
    then it will be derived from the scanner name
    If no name is provided, all supported scanners will be evaluated
    """
    if tool is None:
        typer.echo("Evaluation of all tools is not yet supported")
    else:
        # Note: handling of the scanner selection can lead to the process being aborted
        scanner = _handle_scanner_selection(tool)

        results = evaluation.load_scanner_results_from_file(scanner, file)
        df = evaluation.evaluate_scanner(scanner, results)
        summary = evaluation.create_summary(df, version=get_version_from_result_file(file_name=file))
        typer.echo(f"Here are the results of the evaluation of {tool}:")
        typer.echo(summary)


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
    # Note: handling of the scanner selection can lead to the process being aborted
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

    if out is not None:
        if had_error:
            typer.echo("No results were saved due to an error when starting the scan!")
            return

        # if the specified path is a directory place the resulting file in there named after the scanner
        if out.is_dir():
            version = scanner.get_version() or "?"
            date = datetime.now().strftime("%Y-%m-%d")
            suffix = "json" if "json" in [f.lower() for f in scanner.FORMATS] else "txt"
            # ensure resulting files are written as lowercase for consistency
            out = out / f"{scanner.NAME.lower()}_v{version}_{date}.{suffix}"
        scanner.save_results(results, out)
        typer.echo(f"Successfully saved {len(results)} results in '{out}'")


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
        raise typer.Exit()
    return SCANNERS.get(choice)


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


if __name__ == "__main__":
    app()

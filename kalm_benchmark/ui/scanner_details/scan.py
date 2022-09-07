from pathlib import Path

import streamlit as st

from kalm_benchmark.constants import RunUpdateGenerator, UpdateType
from kalm_benchmark.evaluation.scanner.scanner_evaluator import ScannerBase
from kalm_benchmark.ui.constants import (
    LAST_SCAN_OPTION,
    SELECTED_RESULT_FILE,
    SessionKeys,
)


def show_scan_buttons(tool: ScannerBase) -> None:
    """Show the scan buttons supported by the specified tool
    :param tool: the tool for which the scans can be triggered
    """
    with st.sidebar:
        source = None
        if tool.can_scan_cluster and st.button("▶ Scan cluster"):
            gen = tool.scan_cluster()
            source = "cluster"
        if tool.can_scan_manifests:
            path = Path(st.text_input("Path to manifest(s):", "manifests"))
            if not path.exists():
                st.error(
                    "Invalid path!\n\nPlease ensure the manifests have been generated and are located in this folder!"
                )

            if st.button("▶ Scan manifest(s)", disabled=not path.exists()):
                source = "manifest(s)"
                gen = tool.scan_manifests(path.resolve())
                # change the selection of the result file to the results of this scan
                SEL_FILE_KEY = f"{tool.NAME}_{SELECTED_RESULT_FILE}"
                st.session_state[SEL_FILE_KEY] = LAST_SCAN_OPTION

    if source is not None:
        show_scan_ui(tool, source, gen)


def show_scan_ui(tool: ScannerBase, source: str, generator: RunUpdateGenerator) -> None:
    """Show the UI elements for an ongoing scan

    :param tool: the tool for which the scan is started
    :param source: a string specifying the source of the scan
    :param generator: the generator yielding updates/results for the ongoing scan
    """
    log_messages = st.expander("Scan logs", expanded=True)

    with st.spinner(f"Scanning {source}"):
        try:
            while update := next(generator):
                update_type, msg = update
                if msg is None or len(msg.strip()) == 0:
                    continue
                match update_type:
                    case UpdateType.Warning:
                        log_messages.warning(msg)
                    case UpdateType.Error:
                        log_messages.error(msg)
                    case UpdateType.Progress:
                        # ignore progress updates in UI as spinners value can't be changed
                        pass
                    case _:
                        log_messages.info(msg)
        except StopIteration as exc:
            # as the scan is a generator the final result will be returned via this exception
            # "failed" scans are ignored (i.e. they have no return value)
            if exc.value is not None:
                st.session_state[SessionKeys.LatestScanResult][tool.NAME] = exc.value

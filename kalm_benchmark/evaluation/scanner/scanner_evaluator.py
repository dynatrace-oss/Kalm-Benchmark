import json
import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import auto
from pathlib import Path
from typing import Generator, Optional

from loguru import logger
from strenum import LowercaseStrEnum, StrEnum

from ...constants import RunUpdateGenerator, UpdateType
from ..utils import GeneratorWrapper


@dataclass
class CheckResult:
    check_id: str | None = None
    obj_name: str | None = None
    scanner_check_id: str | None = None
    scanner_check_name: str | None = None
    got: str | None = None
    expected: str | None = None
    checked_path: str | None = None
    severity: str | None = None
    kind: str | None = None
    namespace: str | None = None  # None means it's a cluster resource check
    details: str | None = None
    extra: str | None = None


class CheckCategory(StrEnum):
    AdmissionControl = auto()
    DataSecurity = auto()
    Detection = auto()  # TODO: sure?
    Misc = auto()
    Network = auto()
    IAM = auto()
    Infrastructure = auto()
    Reliability = auto()
    Segregation = auto()
    Vulnerability = auto()
    Workload = auto()


class CheckStatus(LowercaseStrEnum):
    Alert = auto()
    Pass = auto()
    Other = auto()


class ScannerBase(ABC):
    NAME = "_base_"
    NOTES = []
    CI_MODE: bool = False
    CUSTOM_CHECKS: bool | str = False
    SCAN_CLUSTER_CMD: Optional[list] = None
    SCAN_MANIFESTS_CMD: Optional[list] = None
    SCAN_PER_FILE: bool = False
    VERSION_CMD: Optional[list] = None
    RUNS_OFFLINE: bool | str = False
    IMAGE_URL: str | None = None
    FORMATS: list[str] = []

    def __init__(self) -> None:
        self._results = []

    @staticmethod
    def update_version(*args) -> str | None:
        return None

    @classmethod
    @abstractmethod
    def parse_results(cls, results: dict | str | list) -> list[CheckResult]:
        """
        Parses the execution results and returns them.
        :param results: the raw results to parse
        :return: the parsed check results as a list
        """
        pass

    @classmethod
    def categorize_check(cls, check_id: str) -> str:
        """Assign a category to the check depending.
        This method is not required to be implemented.

        :param check_id: the id on basis of which the check should be categorized
        :return: a category for the check as string or None to abstain from assigning a category
        """
        return None

    @classmethod
    def run(cls, cmd: list[str], parse_json: bool = True, stream_process_output: bool = False) -> RunUpdateGenerator:
        """Starts a subprocess with the given command.
        If the process runs into a problem (return code != 0) then `stderr` is forwarded as an
        error message to the caller.
        To be tolerant of various mechanics of the scanners (e.g. CI pipeline support)
        `stdout` is treated as result regardless of the errorcode.

        :param cmd: the command to execute
        :param parse_json: a flag specifying if the results is JSON formatted and should be parsed
        :param stream_process_output: a flag specifying if the process output will be forwarded to the caller
        :return: the results from the started process or an empty list in case of an error
        :yield: in case of an error the information is returned as a status update
        """
        try:
            if stream_process_output:
                output, errors, proc = yield from cls._stream_process_output(cmd)
            else:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    encoding="utf-8",
                )
                output = proc.stdout
                errors = proc.stderr
        except Exception as e:
            yield UpdateType.Error, f"Failed to start scan: {str(e)}"
            # there is nothing to process if the scan could not be started
            return None

        cmd_str = " ".join(cmd)
        has_results = output is not None and len(output) > 0
        result = output
        output_is_json = False  # in case of an error useful information could be contained in output
        if has_results and parse_json:
            try:
                result = json.loads(result)
                output_is_json = True  # the output contains no useful info for debugging
            except json.JSONDecodeError as exc:
                yield UpdateType.Error, f"Malformed JSON response of '{cmd_str}': {exc}"
                result = None

        # handle error code and error message in addation to the "regular" output
        if proc.returncode > 0:
            # if an error message is available, print it below the information that there was an error
            # if there is no proper error message simply print the error-code
            msg_details = (
                f": {os.linesep}{errors} "
                if len(errors) > 0
                else output
                if len(output) > 0 and not output_is_json
                else ""
            )
            level = UpdateType.Warning if has_results else UpdateType.Error
            yield level, f"The process '{cmd_str}' ended with exit-code {proc.returncode}{msg_details}"
        return result

    @staticmethod
    def _stream_process_output(
        cmd: list[str],
    ) -> Generator[tuple[UpdateType, str], None, tuple[str, str, subprocess.CompletedProcess]]:
        """Start the specified command in a sub-process and forward the output to the caller in real-time.

        :param cmd: the command to execute
        :return: a tuple with the full output, error and a reference to the CompletedProcess
        :yield: individual lines output by the process
        """
        proc = subprocess.Popen(
            cmd,
            shell=False,
            bufsize=1,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace",
        )
        stdout = []
        stderr = []
        while True:
            output = proc.stdout.readline()
            if output == "" and proc.poll() is not None:
                break
            stdout.append(output)
            if output:
                yield UpdateType.Info, output.strip()

        return os.linesep.join(stdout), os.linesep.join(stderr), proc

    def load_results(self, path: str | Path) -> list[CheckResult]:
        """Load the specified file with results and parse it
        :param path: the path to the file with the results
                :return: a list of check results
        """
        with open(path, "r", encoding="utf8") as f:
            if Path(path).suffix == ".json":
                res = json.load(f)
            else:
                res = f.readlines()

        self._results = self.parse_results(res)
        return self._results

    def save_results(self, results: list | None = None, path: str | Path = ".") -> None:
        """Save the provided results in the specified file.

        :param results: an optional list of checkresults to save.
            If no results are provided, then the internally stored ones are saved.
        :param path: the path to the file in which the results will be saved
        """
        if results is None:
            results = self._results

        with open(path, "w") as f:
            if path.suffix == ".json":
                json.dump(results, f)
            elif isinstance(results, str):
                # simply write contents as is
                f.write(results)
            else:
                logger.warning(f"Failed to save results to '{str(path)}' because results have an invalid type")

    def get_version(self) -> str | None:
        """Retrieve the version of the tool by executing the corresponding command.

        :return: the version of the tool or None, if the version can't be retrieved
        """
        if self.VERSION_CMD is not None:
            gen = GeneratorWrapper(self.run(self.VERSION_CMD, parse_json=False))
            # consume all updates from the command
            list(gen)
            version = gen.value
            if version is not None and version.startswith("v"):
                version = version[1:]  # drop leading 'v' which some tools print
            return version.strip() if version is not None else ""

        return None

    def scan_manifests(self, path: str | Path, **kwargs) -> RunUpdateGenerator:
        """Start a scan of manifests at the specified location.
        If the path points to a directory, all yaml files within it will be scanned

        :param path: the path to the location with the manifest(s)
        :return: a list of results per file
        """
        if self.SCAN_MANIFESTS_CMD is None:
            yield UpdateType.Error, f"{self.NAME} does not support scanning of manifests"
            return None

        if not self.SCAN_PER_FILE or path.is_file():
            results = yield from self.run(self.SCAN_MANIFESTS_CMD + [str(path)], **kwargs)
        else:  # special handling if tool does not support scanning an entire folder
            results = []
            for p in path.glob("*.yaml"):
                res = yield from self.run(self.SCAN_MANIFESTS_CMD + [str(p)], **kwargs)
                if res is not None and len(res) > 0:
                    results.append(res)
        return results

    def scan_cluster(self, **kwargs) -> RunUpdateGenerator:
        if self.SCAN_CLUSTER_CMD is None:
            yield UpdateType.Error, f"{self.NAME} does not support checking a cluster"
            return
        results = yield from self.run(self.SCAN_CLUSTER_CMD, **kwargs)
        return results

    # sadly, the approach to infer method overriding at class-level doesn't work - only at instance-level
    @property
    def can_scan_manifests(self) -> bool:
        # either command is specified or there is a custom scan implementation
        return self.SCAN_MANIFESTS_CMD is not None or type(self).scan_manifests != ScannerBase.scan_manifests

    @property
    def can_scan_cluster(self) -> bool:
        # either command is specified or there is a custom scan implementation
        return self.SCAN_CLUSTER_CMD is not None or type(self).scan_cluster != ScannerBase.scan_cluster

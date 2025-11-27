import json
import os
import shlex
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import auto
from pathlib import Path
from typing import Generator, Optional, Union

from loguru import logger
from strenum import LowercaseStrEnum, StrEnum

from ...utils.constants import RunUpdateGenerator, UpdateType
from ...utils.eval_utils import GeneratorWrapper

# Bind logger to scan component for proper log filtering
logger = logger.bind(component="scan")


@dataclass
class CheckResult:
    check_id: Optional[str] = None
    obj_name: Optional[str] = None
    scanner_check_id: Optional[str] = None
    scanner_check_name: Optional[str] = None
    got: Optional[str] = None
    expected: Optional[str] = None
    checked_path: Optional[str] = None
    severity: Optional[str] = None
    ccss_score: Optional[float] = None
    ccss_severity: Optional[str] = None
    kind: Optional[str] = None
    namespace: Optional[str] = None  # None means it's a cluster resource check
    details: Optional[str] = None
    extra: Optional[str] = None


class CheckCategory(StrEnum):
    AdmissionControl = auto()
    DataSecurity = auto()
    Detection = auto()
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
    NOTES: list[str] = []
    CI_MODE: bool = False
    CUSTOM_CHECKS: Union[bool, str] = False
    SCAN_CLUSTER_CMD: Optional[list[str]] = None
    SCAN_MANIFESTS_CMD: Optional[list[str]] = None
    SCAN_PER_FILE: bool = False
    VERSION_CMD: Optional[list[str]] = None
    RUNS_OFFLINE: Union[bool, str] = False
    IMAGE_URL: Optional[str] = None
    FORMATS: list[str] = []
    PATH_COLUMNS: list[str] = []

    def __init__(self) -> None:
        self._results: list[CheckResult] = []

    @staticmethod
    def update_version(*args) -> Optional[str]:
        return None

    @classmethod
    @abstractmethod
    def parse_results(cls, results: Union[dict, str, list]) -> list[CheckResult]:
        """
        Parses the execution results and returns them.
        :param results: the raw results to parse
        :return: the parsed check results as a list
        """
        pass

    @classmethod
    def categorize_check(cls, check_id: str) -> str | None:
        """Assign a category to the check depending.
        This method is not required to be implemented.

        :param check_id: the id on basis of which the check should be categorized
        :return: a category for the check as string or None to abstain from assigning a category
        """
        return None

    @classmethod
    def run(
        cls,
        cmd: list[str],
        parse_json: bool = True,
        stream_process_output: bool = False,
    ) -> RunUpdateGenerator:
        """Starts a subprocess with the given command.
        If the process runs into a problem (return code != 0) then `stderr` is forwarded as an
        error message to the caller.
        To be tolerant of various mechanics of the scanners (e.g. CI pipeline support)
        `stdout` is treated as result regardless of the errorcode.

        :param cmd: the command to execute - must be a list of strings for security
        :param parse_json: a flag specifying if the results is JSON formatted and should be parsed
        :param stream_process_output: a flag specifying if the process output will be forwarded to the caller
        :return: the results from the started process or an empty list in case of an error
        :yield: in case of an error the information is returned as a status update
        """
        # Validate command input for security
        if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd):
            yield (
                UpdateType.Error,
                "Command must be a list of strings for security reasons",
            )
            return None

        if not cmd:
            yield UpdateType.Error, "Command cannot be empty"
            return None

        # Sanitize command arguments to prevent injection
        sanitized_cmd = []
        for arg in cmd:
            # Basic validation - reject arguments with shell metacharacters that could be dangerous
            if any(
                char in arg
                for char in [
                    ";",
                    "|",
                    "&",
                    "$",
                    "`",
                    "(",
                    ")",
                    "<",
                    ">",
                    "\n",
                    "\r",
                ]
            ):
                yield (
                    UpdateType.Warning,
                    f"Command argument contains potentially dangerous characters: {arg}",
                )
            sanitized_cmd.append(str(arg))  # Ensure all arguments are strings

        try:
            if stream_process_output:
                output, errors, proc = yield from cls._stream_process_output(sanitized_cmd)
            else:
                proc = subprocess.run(
                    sanitized_cmd,
                    capture_output=True,
                    encoding="utf-8",
                    shell=False,  # Explicitly disable shell to prevent injection
                )
                output = proc.stdout
                errors = proc.stderr
        except Exception as e:
            yield UpdateType.Error, f"Failed to start scan: {str(e)}"
            # there is nothing to process if the scan could not be started
            return None

        cmd_str = shlex.join(sanitized_cmd)  # Use shlex.join for safe command display
        has_results = output is not None and len(output) > 0
        result: Union[str, dict, list, None] = output
        output_is_json = False  # in case of an error useful information could be contained in output
        if has_results and parse_json:
            try:
                result = json.loads(output)
                output_is_json = True  # the output contains no useful info for debugging
            except json.JSONDecodeError as exc:
                yield (
                    UpdateType.Error,
                    f"Malformed JSON response of '{cmd_str}': {exc}",
                )
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
            yield (
                level,
                f"The process '{cmd_str}' ended with exit-code {proc.returncode}{msg_details}",
            )
        return result

    @staticmethod
    def _stream_process_output(
        cmd: list[str],
    ) -> Generator[tuple[UpdateType, str], None, tuple[str, str, subprocess.Popen]]:
        """Start the specified command in a sub-process and forward the output to the caller in real-time.

        :param cmd: the command to execute - must be a list of strings for security
        :return: a tuple with the full output, error and a reference to the Popen process
        :yield: individual lines output by the process
        """
        proc = subprocess.Popen(
            cmd,
            shell=False,  # Explicitly disable shell to prevent injection
            bufsize=1,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace",
        )
        stdout: list[str] = []
        stderr: list[str] = []

        try:
            while True:
                if proc.stdout is None:
                    break
                output = proc.stdout.readline()
                if output == "" and proc.poll() is not None:
                    break
                stdout.append(output)
                if output:
                    yield UpdateType.Info, output.strip()

            # Read any remaining stderr
            if proc.stderr is not None:
                stderr_content = proc.stderr.read()
                if stderr_content:
                    stderr.append(stderr_content)
        finally:
            # Ensure process is properly closed
            if proc.poll() is None:
                proc.terminate()
                proc.wait()

        return os.linesep.join(stdout), os.linesep.join(stderr), proc

    def load_results(self, path: Union[str, Path]) -> list[CheckResult]:
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

    def save_results(self, results: Optional[list] = None, path: Union[str, Path] = ".") -> None:
        """Save the provided results in the specified file.

        :param results: an optional list of checkresults to save.
            If no results are provided, then the internally stored ones are saved.
        :param path: the path to the file in which the results will be saved
        """
        if results is None:
            results = self._results

        path_obj = Path(path)
        with open(path_obj, "w") as f:
            if path_obj.suffix == ".json":
                json.dump(results, f)
            elif isinstance(results, str):
                # simply write contents as is
                f.write(results)
            else:
                logger.warning(f"Failed to save results to '{str(path_obj)}' because results have an invalid type")

    def get_version(self) -> Optional[str]:
        """Retrieve the version of the tool by executing the corresponding command.

        :return: the version of the tool or None, if the version can't be retrieved
        """
        if self.VERSION_CMD is not None:
            gen = GeneratorWrapper(self.run(self.VERSION_CMD, parse_json=False))
            # consume all updates from the command
            list(gen)
            version = gen.value
            if version is not None and isinstance(version, str) and version.startswith("v"):
                version = version[1:]  # drop leading 'v' which some tools print
            return version.strip() if version is not None and isinstance(version, str) else None

        return None

    def scan_manifests(self, path: Union[str, Path], **kwargs) -> RunUpdateGenerator:
        """Start a scan of manifests at the specified location.
        If the path points to a directory, all yaml files within it will be scanned

        :param path: the path to the location with the manifest(s)
        :return: a list of parsed CheckResult objects
        """
        if self.SCAN_MANIFESTS_CMD is None:
            yield (
                UpdateType.Error,
                f"{self.NAME} does not support scanning of manifests",
            )
            return None

        path_obj = Path(path)
        if not self.SCAN_PER_FILE or path_obj.is_file():
            logger.info(f"{self.NAME}: Scanning path {path_obj} as {'file' if path_obj.is_file() else 'directory'}")
            raw_results = yield from self.run(self.SCAN_MANIFESTS_CMD + [str(path_obj)], **kwargs)
        else:  # special handling if tool does not support scanning an entire folder
            yaml_files = list(path_obj.rglob("*.yaml"))
            logger.info(
                f"{self.NAME}: Scanning directory {path_obj} with {len(yaml_files)} YAML files (SCAN_PER_FILE=True)"
            )
            if len(yaml_files) == 0:
                logger.warning(f"{self.NAME}: No YAML files found in {path_obj}")
            raw_results = []
            for file_idx, p in enumerate(yaml_files):
                res = yield from self.run(self.SCAN_MANIFESTS_CMD + [str(p)], **kwargs)
                if res is not None and len(res) > 0:
                    raw_results.append(res)

        # Parse raw results into CheckResult objects
        if raw_results is not None:
            try:
                parsed_results = self.parse_results(raw_results)
                logger.info(
                    f"{self.NAME}: Successfully parsed {len(parsed_results) if parsed_results else 0} check results"
                )
                return parsed_results
            except Exception as e:
                logger.error(f"{self.NAME}: Failed to parse results: {e}")
                yield (
                    UpdateType.Error,
                    f"Failed to parse results from {self.NAME}: {e}",
                )
                return []

        logger.warning(f"{self.NAME}: No raw results to parse")
        return []

    def scan_cluster(self, **kwargs) -> RunUpdateGenerator:
        if self.SCAN_CLUSTER_CMD is None:
            yield (
                UpdateType.Error,
                f"{self.NAME} does not support checking a cluster",
            )
            return []
        raw_results = yield from self.run(self.SCAN_CLUSTER_CMD, **kwargs)

        # Parse raw results into CheckResult objects
        if raw_results is not None:
            try:
                parsed_results = self.parse_results(raw_results)
                return parsed_results
            except Exception as e:
                yield (
                    UpdateType.Error,
                    f"Failed to parse results from {self.NAME}: {e}",
                )
                return []

        return []

    # sadly, the approach to infer method overriding at class-level doesn't work - only at instance-level
    @property
    def can_scan_manifests(self) -> bool:
        # either command is specified or there is a custom scan implementation
        return self.SCAN_MANIFESTS_CMD is not None or type(self).scan_manifests != ScannerBase.scan_manifests

    @property
    def can_scan_cluster(self) -> bool:
        # either command is specified or there is a custom scan implementation
        return self.SCAN_CLUSTER_CMD is not None or type(self).scan_cluster != ScannerBase.scan_cluster

    def scan_helm_chart(
        self,
        chart_path: Union[str, Path],
        release_name: str = "test-release",
        namespace: str = "default",
        **kwargs,
    ) -> RunUpdateGenerator:
        """Scan a Helm chart by rendering it to manifests first.

        :param chart_path: Path to Helm chart directory or Artifact Hub URL
        :param release_name: Name for the Helm release
        :param namespace: Kubernetes namespace for the release
        :return: Parsed CheckResult objects from scanning the rendered manifests
        """
        from ...utils.helm_operations import scan_helm_chart_generator

        return scan_helm_chart_generator(chart_path, self, release_name, namespace)

    def scan_popular_charts(
        self,
        num_charts: int = 10,
        release_name: str = "test-release",
        namespace: str = "default",
        **kwargs,
    ) -> RunUpdateGenerator:
        """Scan popular Helm charts by downloading and rendering them.

        :param num_charts: Number of popular charts to download and scan
        :param release_name: Base name for Helm releases
        :param namespace: Kubernetes namespace for the releases
        :return: Combined parsed CheckResult objects from all scanned charts
        """
        from ...utils.helm_operations import scan_popular_charts_generator

        return scan_popular_charts_generator(num_charts, self, release_name, namespace)

    @property
    def can_scan_helm(self) -> bool:
        """Check if the scanner can scan Helm charts.

        Helm scanning is available for any scanner that can scan manifests,
        since we render Helm charts to manifests first.
        """
        return self.can_scan_manifests

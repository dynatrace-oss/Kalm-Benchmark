import re

from loguru import logger

from kalm_benchmark.utils.path_normalization import normalize_kubesec_path

from .scanner_evaluator import CheckResult, CheckStatus, ScannerBase

# Bind logger to scan component for proper log filtering
logger = logger.bind(component="scan")


class Scanner(ScannerBase):
    NAME = "kubesec"
    SCAN_MANIFESTS_CMD = ["kubesec", "scan", "-f", "json", "--exit-code", "0"]
    SCAN_PER_FILE = True
    IMAGE_URL = "http://casual-hosting.s3.amazonaws.com/kubesec-logo.png"
    RUNS_OFFLINE = True
    CI_MODE = True
    FORMATS = ["JSON", "Template"]
    VERSION_CMD = ["kubesec", "version"]
    PATH_COLUMNS = ["checked_path"]

    @classmethod
    def parse_results(cls, results: list[list[dict]]) -> list[CheckResult]:
        """
        Parses the raw results and turns them into a flat list of check results.
        The results consists of a list of the results per file.
        Per file is a dict per resource within that file.
        For each resource there is a list of 'advises' by the tool, which are the individual checks.

        :param results: the results which will be parsed
        :returns: the list of check results
        """
        logger.debug(f"Kubesec: Parsing results from {len(results)} files")
        check_id_pattern = re.compile(r"^(\w+(?:-\d+)+)")  # match the first letters and then the numbers following it
        check_results = []
        for file_idx, file in enumerate(results):
            # Handle case where kubesec returns flat list instead of nested list
            if isinstance(file, dict):
                # Single resource returned as dict, wrap in list
                file_resources = [file]
            else:
                # List of resources
                file_resources = file

            for resource_idx, resource in enumerate(file_resources):
                try:
                    kind, name = resource["object"].split("/")
                except (KeyError, ValueError) as e:
                    logger.error(f"Kubesec: Failed to parse resource object: {resource.get('object', 'unknown')}: {e}")
                    continue

                m = check_id_pattern.search(name)
                check_id = m.group(1) if m is not None else None
                scoring = resource["scoring"]

                logger.debug(f"Kubesec: Processing resource {file_idx}.{resource_idx}: {kind}/{name} with check ID {check_id}")

                if len(scoring) == 0:
                    details = resource.get("message", "Unknown kubesec error")
                    is_valid = resource.get("valid", False)

                    if details == "This resource kind is not supported by kubesec":
                        logger.debug(f"Kubesec: Resource {kind}/{name} is not supported")
                    else:
                        logger.warning(f"Kubesec: Resource {kind}/{name} has no scoring: {details}")

                    if is_valid:
                        # provide the message as id so it can be analyzed in the UI
                        scanner_check_id = resource.get("message", "Unknown validation issue")
                        checked_path = "kind" if details == "This resource kind is not supported by kubesec" else None
                    elif ":" in details:
                        # Handle schema validation errors (e.g., kubeconform failures)
                        try:
                            checked_path, *_, msg = details.split(":")
                            checked_path = _normalize_path(checked_path)
                            scanner_check_id = msg.strip()
                            logger.error(
                                f"Kubesec: Schema validation failed for {kind}/{name} at {checked_path}: {msg.strip()}"
                            )
                        except Exception as e:
                            logger.error(f"Kubesec: Failed to parse error details: {details}: {e}")
                            checked_path = None
                            scanner_check_id = details
                    else:
                        # Check if it's a schema validation error for better logging
                        if cls._is_schema_validation_error(details):
                            logger.warning(f"Kubesec: Schema validation issue for {kind}/{name}: {details}")
                        else:
                            logger.error(f"Kubesec: Validation failed for {kind}/{name}: {details}")
                        checked_path = None
                        scanner_check_id = details

                    extra = (
                        ""
                        if resource.get("valid", False)
                        else "Failed to parse the resource (possible schema validation issue)"
                    )

                    check_results.append(
                        CheckResult(
                            check_id=check_id,
                            scanner_check_id=scanner_check_id,
                            checked_path=checked_path,
                            obj_name=name,
                            kind=kind,
                            details=details,
                            extra=extra,
                            got=CheckStatus.Other,
                        )
                    )
                    continue

                # Process both 'critical' and 'advise' sections
                critical_list = scoring.get("critical", [])
                advise_list = scoring.get("advise", [])

                # Process critical issues (negative points = high severity)
                for critical in critical_list:
                    try:
                        # Ensure critical is a dictionary, not a string
                        if not isinstance(critical, dict):
                            logger.error(f"Kubesec: Expected dict for critical item, got {type(critical)}: {critical}")
                            continue

                        checked_path = _normalize_path(critical["selector"])
                    except Exception as e:
                        logger.error(
                            f"Kubesec: Failed to normalize path '{critical.get('selector', 'unknown')}' "
                            f"for {kind}/{name}: {e}"
                        )
                        checked_path = critical.get("selector", "unknown")

                    try:
                        # Map kubesec points to standard severity levels (consistent with other scanners)
                        points = critical["points"]
                        if points <= -20:  # Very severe issues like -30
                            severity = "CRITICAL"
                        elif points <= -7:  # High severity issues like -9, -7
                            severity = "HIGH"
                        else:  # Other negative values
                            severity = "MEDIUM"
                    except (KeyError, TypeError) as e:
                        logger.error(f"Kubesec: Failed to process critical points for {kind}/{name}: {e}")
                        severity = "HIGH"  # Default for critical issues

                    check_results.append(
                        CheckResult(
                            check_id=check_id,
                            obj_name=name,
                            scanner_check_id=critical["id"],
                            got=CheckStatus.Alert,  # critical issues are alerts
                            checked_path=checked_path,
                            severity=severity,  # Use standard severity labels
                            kind=kind,
                            details=critical["reason"],
                        )
                    )

                # Process advisory recommendations (positive points = low severity)
                for advise in advise_list:
                    try:
                        # Ensure advise is a dictionary, not a string
                        if not isinstance(advise, dict):
                            logger.error(f"Kubesec: Expected dict for advise item, got {type(advise)}: {advise}")
                            continue

                        checked_path = _normalize_path(advise["selector"])
                    except Exception as e:
                        logger.error(
                            f"Kubesec: Failed to normalize path '{advise.get('selector', 'unknown')}' "
                            f"for {kind}/{name}: {e}"
                        )
                        checked_path = advise.get("selector", "unknown")

                    try:
                        # Map kubesec advisory points to standard severity levels
                        points = advise["points"]
                        if points >= 3:  # Higher value recommendations like AppArmor
                            severity = "LOW"
                        else:  # Standard recommendations like +1
                            severity = "INFO"
                    except (KeyError, TypeError) as e:
                        logger.error(f"Kubesec: Failed to process advise points for {kind}/{name}: {e}")
                        severity = "INFO"  # Default for advisory items

                    check_results.append(
                        CheckResult(
                            check_id=check_id,
                            obj_name=name,
                            scanner_check_id=advise["id"],
                            got=CheckStatus.Alert,  # recommendations are alerts
                            checked_path=checked_path,
                            severity=severity,  # Use standard severity labels
                            kind=kind,
                            details=advise["reason"],
                        )
                    )

        logger.info(f"Kubesec: Generated {len(check_results)} check results from {len(results)} files")

        return check_results

    def get_version(self) -> str:
        """Retrieve the hardcoded version number of the tool.
        The tool has a version command, but it's not working (see https://github.com/controlplaneio/kubesec/issues/337)
        :return: the version number of the tool
        """
        return "2.12.0"

    @classmethod
    def _is_schema_validation_error(cls, message: str) -> bool:
        """Check if the error is related to schema validation issues.

        :param message: Error message to check
        :return: True if it's a schema validation error
        """
        schema_error_indicators = [
            "validation failed",
            "schema",
            "kubeconform",
            "invalid field",
            "unknown field",
            "field not found",
        ]
        return any(indicator in message.lower() for indicator in schema_error_indicators)


def _normalize_path(path: str) -> str:
    return normalize_kubesec_path(path)

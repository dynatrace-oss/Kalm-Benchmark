from pathlib import Path

from loguru import logger

from kalm_benchmark.constants import RunUpdateGenerator

from ..utils import normalize_path
from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

CONTROL_CATEGORY = {
    "C-0001": CheckCategory.Workload,
    "C-0002": CheckCategory.IAM,
    "C-0004": CheckCategory.Workload,
    "C-0005": CheckCategory.Infrastructure,
    "C-0006": CheckCategory.PodSecurity,
    "C-0007": CheckCategory.IAM,
    "C-0009": CheckCategory.Workload,
    "C-0011": CheckCategory.Network,
    "C-0012": CheckCategory.DataSecurity,
    "C-0013": CheckCategory.PodSecurity,
    "C-0014": CheckCategory.IAM,
    "C-0015": CheckCategory.IAM,
    "C-0016": CheckCategory.PodSecurity,
    "C-0017": CheckCategory.PodSecurity,
    "C-0018": CheckCategory.PodSecurity,
    "C-0019": CheckCategory.PodSecurity,
    "C-0020": CheckCategory.PodSecurity,
    "C-0021": CheckCategory.Workload,
    "C-0024": CheckCategory.PodSecurity,
    "C-0025": CheckCategory.PodSecurity,
    "C-0026": CheckCategory.Workload,
    "C-0028": CheckCategory.PodSecurity,
    "C-0030": CheckCategory.Network,
    "C-0031": CheckCategory.IAM,
    "C-0033": CheckCategory.Workload,
    "C-0034": CheckCategory.PodSecurity,
    "C-0035": CheckCategory.IAM,
    "C-0036": CheckCategory.Infrastructure,
    "C-0037": CheckCategory.IAM,
    "C-0038": CheckCategory.PodSecurity,
    "C-0039": CheckCategory.Infrastructure,
    "C-0041": CheckCategory.PodSecurity,
    "C-0042": CheckCategory.PodSecurity,
    "C-0044": CheckCategory.PodSecurity,
    "C-0045": CheckCategory.PodSecurity,
    "C-0046": CheckCategory.PodSecurity,
    "C-0047": CheckCategory.Workload,
    "C-0048": CheckCategory.PodSecurity,
    "C-0049": CheckCategory.Network,
    "C-0050": CheckCategory.PodSecurity,
    "C-0052": CheckCategory.Infrastructure,
    "C-0053": CheckCategory.IAM,
    "C-0054": CheckCategory.Network,
    "C-0055": CheckCategory.PodSecurity,
    "C-0056": CheckCategory.PodSecurity,
    "C-0057": CheckCategory.PodSecurity,
    "C-0058": CheckCategory.PodSecurity,
    "C-0059": CheckCategory.Workload,
    "C-0060": CheckCategory.Workload,
    "C-0061": CheckCategory.Workload,
    "C-0062": CheckCategory.PodSecurity,
    "C-0063": CheckCategory.IAM,
    "C-0064": CheckCategory.PodSecurity,
    "C-0065": CheckCategory.IAM,
    "C-0066": CheckCategory.Infrastructure,
    "C-0067": CheckCategory.Infrastructure,
    "C-0068": CheckCategory.AdmissionControl,
    "C-0069": CheckCategory.Infrastructure,
    "C-0070": CheckCategory.Infrastructure,
    "C-0071": CheckCategory.Infrastructure,
    "C-0073": CheckCategory.Workload,
    "C-0074": CheckCategory.PodSecurity,
    "C-0075": CheckCategory.PodSecurity,
    "C-0076": CheckCategory.Workload,
    "C-0077": CheckCategory.Workload,
    "C-0078": CheckCategory.Workload,  # Images from allowed registry
    "C-0079": CheckCategory.PodSecurity,
    # "C-0080": CheckCategory.SupplyChain,  # gone? 
    "C-0081": CheckCategory.Vulnerability,   # CVE-2022-24348-argocddirtraversal
    "C-0082": CheckCategory.Infrastructure,
}


class Scanner(ScannerBase):
    NAME = "Kubescape"
    IMAGE_URL = "https://www.armosec.io/wp-content/uploads/2023/01/Group-1000005089.svg"
    FORMATS = ["Plain", "JSON", "JUnit", "Prometheus", "PDF"]
    SCAN_MANIFESTS_CMD = ["kubescape", "scan", "--format", "json", "--verbose"]
    RUNS_OFFLINE = "artifacts/frameworks can be downloaded"
    CUSTOM_CHECKS = True
    VERSION_CMD = ["kubescape", "version"]

    def scan_manifests(self, path: str | Path) -> RunUpdateGenerator:
        """Start a scan of manifests at the specified location.
        If the path points to a directory, all yaml files within it will be scanned

        :param path: the path to the location with the manifest(s)
        :return: a list of results per file
        """
        if path.is_dir():
            path = path / "*.yaml"
        results = yield from super().scan_manifests(path)
        return results

    def scan_cluster(self) -> RunUpdateGenerator:
        """
        Run the application against the benchmark cluster
        :param framework: the set of pre-defined checks to execute
        :returns the results as dictionary
        """
        cmd = ["kubescape", "scan", "--format", "json", "-s", "--verbose"]
        results = yield from self.run(cmd)
        return results

    @classmethod
    def parse_results(cls, results: dict) -> list[CheckResult]:
        """
        Parses the raw results and turns them into a flat list of check results.
        :param results: the results which will be parsed
        :returns: the list of check results
        """
        ctrls = []
        for fw_result in results:
            ctrls += _parse_control_reports(fw_result["controlReports"])
        return ctrls

    @classmethod
    def categorize_check(cls, check_id: str) -> str:
        return CONTROL_CATEGORY.get(check_id, None)

    def get_version(self) -> str:
        """Retrieve the version number of the tool by executing the corresponding command.
        The tool returns the info in the format "Your vurrent version is: v<version>".
        :return: the version of the tool
        """
        raw_version = super().get_version()
        version = raw_version[raw_version.rindex("v") + 1 :]
        return version.strip()


def _parse_control_reports(reports: list[dict]) -> list[CheckResult]:
    results = []
    for ctrl in reports:
        ctrl_id = ctrl["id"]
        name = ctrl["name"]

        rule_reports = _parse_rule_reports(ctrl["ruleReports"])
        if len(ctrl["ruleReports"]) == 0:
            rule_reports = [CheckResult(details="empty list of ruleReports")]

        # set correct scanner check id for all parsed check results
        for res in rule_reports:
            res.scanner_check_id = ctrl_id
            res.scanner_check_name = name
            res.severity = ctrl["baseScore"]
        results += rule_reports

    return results


def _normalize_status(status: str) -> str:
    if status == "failed":
        return CheckStatus.Alert
    elif status == "success":
        return CheckStatus.Pass
    else:
        logger.warning(f"Unknown status while parsing kubescape: '{status}'. Expected either 'failed' or 'success")
        return ""


def _parse_rule_reports(reports: list[dict]) -> list[CheckResult]:
    results = []
    for rule in reports:
        if rule["ruleResponses"] is not None:
            responses = _parse_rule_responses(rule["ruleResponses"])
            results += responses
        else:
            return [
                CheckResult(
                    check_id=None,
                    got=_normalize_status(rule["ruleStatus"]["status"]),
                    details="no ruleResponses present",
                )
            ]
    return results


def _parse_rule_responses(responses: list[dict]) -> list[CheckResult]:
    results = []
    for r in responses:
        checked_path = _get_check_path(r["failedPaths"], r["fixPaths"])
        status = _normalize_status(r["ruleStatus"])
        details = ", ".join(r["failedPaths"] or [""])

        api_objs = r["alertObject"]["k8sApiObjects"]
        for obj in api_objs:
            checked_path = _get_check_path(r["failedPaths"], r["fixPaths"], obj.get("relatedObjects", None))
            res = _parse_api_object(obj)
            results.append(CheckResult(got=status, details=details, checked_path=checked_path, **res))
    return results


def _get_check_path(
    failed_paths: list[str] | None = None,
    fix_paths: list[dict[str, str]] | None = None,
    related_objects: list[dict] | None = None,
) -> str:
    if failed_paths is None and fix_paths is None:
        return None

    paths = []
    if failed_paths is not None:
        paths += failed_paths
    if fix_paths is not None:
        paths += [fix_path["path"] for fix_path in fix_paths]

    normalized_paths = [normalize_path(p, related_objects) for p in paths]
    return "|".join(set(normalized_paths))


def _parse_api_object(obj: dict) -> dict:
    check_infos = []
    meta = obj.get("metadata", None)
    check = {"check_id": None}
    if meta is not None:
        check = _parse_object_meta(meta)
    check["kind"] = obj["kind"]

    # ServiceAccounts have the namespace and name on the top level and not on the metaobject
    if check["kind"] == "ServiceAccount":
        check["namespace"] = obj.get("namespace", None)

    if "obj_name" not in check:
        check["obj_name"] = obj["name"]
    check_infos.append(check)
    if "relatedObjects" in obj:
        for rel_obj in obj["relatedObjects"]:
            check = _parse_object_meta(rel_obj.get("metadata", None))
            check["kind"] = rel_obj["kind"]
            check_infos.append(check)

    res = _consolidate_objects(check_infos)
    return res


def _consolidate_objects(check_infos: list[dict]) -> dict:
    """
    Consolidate/pick check infos from multiple objects with the following preferences:
    1) if there is a single object with a valid check_id, use all  the information of that object
    2) if multiple objects have a valid check_id: use the single object where the id is part of it's name
    3) if none ore more than 1 object have a valid name, merge the check informations
    :param check_infos: the list of check_informations extracted from objects
    :returns: a single dictionary with the check information resulting from the consodliation.
    """
    num_objects = len(check_infos)
    if num_objects == 1:  # there is nothing to consolidate when only 1 object is there
        return check_infos[0]
    elif num_objects == 0:
        logger.error("no object has check meta attached, which should never happen!")

    # filter out objects without a check id
    rel_checks = [check for check in check_infos if check.get("check_id", None) is not None]
    # if exactly one object has the check meta info, only it is relevant
    if len(rel_checks) == 1:
        return rel_checks[0]
    elif len(rel_checks) == 0:
        return _merge_dicts(check_infos)

    # check id in name is case insensitive
    check_id = rel_checks[0]["check_id"].lower()
    # prefer objects where name starts with check_id
    named_objects = [check for check in rel_checks if check["obj_name"].startswith(check_id)]
    if len(named_objects) == 1:
        return rel_checks[0]

    return _merge_dicts(check_infos)


def _merge_dicts(dicts: list[dict]) -> dict:
    res = {}
    for d in dicts:
        for k, v in d.items():
            if k not in res:
                res[k] = v
            elif res[k] is None:
                res[k] = v
            elif v is not None and v not in res[k].split(";"):
                res[k] += ";" + v
    return res


def _parse_object_meta(meta: dict) -> dict[str, str]:
    return {
        "check_id": meta.get("labels", {}).get("check", None) if "labels" in meta else None,
        # default to 'pass', because benchmark is designed to have only on object that should actually trigger an alert
        # missing expect annotation means the check was not designed to trigger for that ojbect
        # "expected": meta.get("annotations", {}).get("expected", CheckStatus.Pass),
        "obj_name": meta["name"],
        "namespace": meta.get("namespace", None),
    }

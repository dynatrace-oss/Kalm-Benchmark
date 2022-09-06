from cdk8s import Chart
from constructs import Construct

from .cdk8s_imports import k8s
from .constants import MAIN_NS, CheckKey, CheckStatus
from .utils import sanitize_name


class Check(Chart):
    """
    Base class for checks which takes care of placing the check information
    as labels/annotations on the resulting manifest
    """

    def __init__(
        self,
        scope: Construct,
        check_id: str,
        name: str,
        expect: str = CheckStatus.Alert,
        descr: str | None = None,
        check_path: str | list[str] | None = None,
        forwarded_kwargs: dict | None = None,  # don't process other kwargs for the resources
        namespace: str = MAIN_NS,
    ):
        """
        Initialize a new check with the specified meta information
        :param scope: the scope of the resulting chart - relevant for cdk8s
        :param check_id: the id of the implemented check
        :param name: name of the check
        :param expect: the expected outcome. Either "ok" or "fail".
        :param descr: an optional description
        :param check_path: the path(s) which is the essence of the check
        :param name: name of the check
        :param namespace: the optional namespace of the generated resources.
        By default, they will be placed in the main namespace for the benchmark.
        If a resource is not namespaced, this field will be ignored.
        :param kwargs: any additional keyword arguments will be ignored
        """
        # avoid duplicate check id prefix, if name already is constructed outside
        _name = f"{check_id}-{name}" if not name.startswith(check_id.lower()) else name
        self.name = sanitize_name(_name)
        labels = {CheckKey.CheckId: check_id, "app.kubernetes.io/part-of": "kalm-benchmark"}

        if check_path is None:
            check_path = determine_check_path(forwarded_kwargs)
        elif isinstance(check_path, list):
            check_path = "|".join(check_path)
        annotations = {CheckKey.Expect: expect, CheckKey.CheckPath: check_path}
        if descr is not None:
            annotations[CheckKey.Description] = descr

        self.meta = k8s.ObjectMeta(
            name=self.name,
            labels=labels,
            annotations={str(k): str(v) for k, v in annotations.items()},
        )

        super().__init__(scope, self.name, namespace=namespace, labels=labels)


def determine_check_path(kwargs: dict) -> str:
    return None


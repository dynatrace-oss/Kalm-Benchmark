from cdk8s import Chart
from constructs import Construct

from ..utils.data.validation import sanitize_kubernetes_name as sanitize_name
from kalm_benchmark.utils.scoring import ccss_severity_from_base_score
from .cdk8s_imports import k8s
from .constants import MAIN_NS, CheckKey, CheckStatus


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
        standards: list[dict] | None = None,
        forwarded_kwargs: dict | None = None,  # don't process other kwargs for the resources
        namespace: str = MAIN_NS,
        annotations: dict | bool = True,
        ccss: float | None = None,
    ):
        """
        Initialize a new check with the specified meta information
        :param scope: the scope of the resulting chart - relevant for cdk8s
        :param check_id: the id of the implemented check
        :param name: name of the check
        :param expect: the expected outcome. Either "ok" or "fail".
        :param descr: an optional description
        :param check_path: the path(s) which is the essence of the check
        :param forwarded_kwargs: don't process other kwargs for the resources
        :param namespace: the optional namespace of the generated resources.
        By default, they will be placed in the main namespace for the benchmark.
        If a resource is not namespaced, this field will be ignored.
        :param annotations: optional annotations for the check
        """
        # avoid duplicate check id prefix, if name already is constructed outside
        _name = f"{check_id}-{name}" if not name.startswith(check_id.lower()) else name
        self.name = sanitize_name(_name)
        labels = {CheckKey.CheckId: check_id}

        check_path = "|".join(check_path) if isinstance(check_path, list) else check_path or ""

        if annotations is not None:
            annotations = {CheckKey.Expect: expect, CheckKey.CheckPath: check_path}
            if descr is not None:
                annotations[CheckKey.Description] = descr

            # ensure annotations are only strings as expected by cdk8s
            annotations = {str(k): str(v) for k, v in annotations.items()}

        if standards is not None:
            if annotations is None:
                annotations = {}
            annotations["standards"] = str(standards)

        if ccss is not None:
            if annotations is None:
                annotations = {}
            annotations["ccss_score"] = str(ccss)
            annotations["ccss_severity"] = ccss_severity_from_base_score(ccss)

        self.meta = Meta(
            name=self.name,
            labels=labels,
            annotations=annotations,
        )

        super().__init__(scope, self.name, namespace=namespace, labels=self.meta.labels)


class Meta(k8s.ObjectMeta):
    def __init__(
        self,
        *,
        annotations: dict | None = None,
        name: str | None = None,
        labels: dict | None = None,
        namespace: str | None = None,
        **kwargs,
    ) -> None:
        if labels is None:
            labels = {}
        labels = {"app.kubernetes.io/part-of": "kalm-benchmark", **labels}

        super().__init__(name=name, annotations=annotations, labels=labels, namespace=namespace, **kwargs)

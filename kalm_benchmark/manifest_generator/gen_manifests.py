from pathlib import Path

from cdk8s import App, Chart, YamlOutputType
from constructs import Construct

from kalm_benchmark.manifest_generator.check import Meta

from .cdk8s_imports import k8s
from .constants import MAIN_NS, UNRESTRICTED_NS
from .gen_namespaces import (
    SetupBenchmarkNamespace,
    gen_namespace_resource_checks,
    gen_network_policy_checks,
)
from .pod_security_admission import gen_pod_security_admission_checks
from .rbac import gen_rbac
from .workload.gen_workloads import gen_workloads


class DefaultLowPriorityClass(Chart):
    """
    A priority class which will serve as a default for all pods.
    This class itself is not part of a particular check.
    """

    def __init__(self, scope: Construct, name: str):
        """
        Creates a PriorityClass in the provided scope with the given name
        :param scope: the scope of the resource
        :param name: the name of the resource
        """
        super().__init__(scope, f"_{name}")

        metadata = Meta(name=name)

        k8s.KubePriorityClass(
            self,
            name,
            metadata=metadata,
            value=1000,
            preemption_policy="Never",
            global_default=True,
            description="Default priority class for all pods",
        )


def generate_manifests(app: App) -> list[Chart]:
    """
    Collects all the preconfigured manifests and places them in the same cdk8s "app".
    :param app: the cdk8s app which represent the scope of the checks.
    :returns: list of charts, which is also set on the app instance.
    """
    DefaultLowPriorityClass(app, "default-priority")
    SetupBenchmarkNamespace(app, MAIN_NS)
    SetupBenchmarkNamespace(app, UNRESTRICTED_NS, with_resource_restrictions=False)
    gen_namespace_resource_checks(app)
    # gen_psps(app)  # PSPs have been deprecated; re-enable once Validating Admission Policies should be checked
    gen_pod_security_admission_checks(app)
    gen_rbac(app)
    gen_network_policy_checks(app)
    gen_workloads(app, MAIN_NS, UNRESTRICTED_NS)

    return app.charts


def create_manifests(out_dir: Path | str | None = "manifests", file_per_check: bool = True) -> int:
    """
    Generates all preconfigured manifests and places them in the output directory.
    In total, one file per check and several auxiliary manifests will be created.
    The name of the generated files is made up of the check id, name provided in the check
    and the general output file extension.
    :param out_dir: the folder where the generated manifests will be written to.
    Defaults to the `manifests` folder in the working directory.
    :param file_per_check: flag specifying if a dedicated file will be created per check.
        If false, all checks will be written to a single file.
    :return: the number of generated files
    """
    yaml_output_type = YamlOutputType.FILE_PER_CHART if file_per_check else YamlOutputType.FILE_PER_APP
    app = App(outdir=out_dir, output_file_extension=".yaml", yaml_output_type=yaml_output_type)
    generate_manifests(app)
    app.synth()

    return len(app.charts)

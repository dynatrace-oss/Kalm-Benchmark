from typing import Optional

from constructs import Construct
from loguru import logger

from .cdk8s_imports import k8s


class NetworkPolicy(Construct):
    """
    A cdk8s building block wrapping a Kubernetes NetworkPolicy
    """

    def __init__(
        self,
        scope: Construct,
        name: str,
        meta: k8s.ObjectMeta,
        egress: Optional[list[dict]] = None,
        ingress: Optional[list[dict]] = None,
        pod_selector: Optional[dict] = None,
        policy_types: Optional[list[str]] = None,
    ):
        """
        Instantiates a new NetworkPolicy with the specified parameters.

        :param scope: the cdk8s scope in which the resources will be placed
        :param name: the name of the resource.
        :param meta: the metadata of the parent object. Will be used to create the
            metadata of this object.
        :param egress: a collection of engress rules, defaults to None
        :param ingress: a collection of ingress rules, defaults to None
        :param pod_selector: the mandatory selector of the target pods, defaults to {}
        :param policy_types: the types of policies (ingress/egress) covered by the rule,
            defaults to both types
        """
        super().__init__(scope, name + "_netpol")

        if pod_selector is None:
            pod_selector = {}

        if policy_types is None:
            # default to Egress and Ingress
            policy_types = ["Egress", "Ingress"]
        elif policy_types == []:
            # don't show the policyTypes in the manifest if it's empty
            policy_types = None

        egress_rules = None
        if egress is not None:
            egress_rules = [self._parse_egress_rule(r) for r in egress]

        if ingress is not None:
            logger.warning("Ingress rules are not yet supported!")
            ingress = None

        k8s.KubeNetworkPolicy(
            self,
            "netpol",
            metadata=meta,
            spec=k8s.NetworkPolicySpec(
                pod_selector=pod_selector, egress=egress_rules, ingress=ingress, policy_types=policy_types
            ),
        )

    @staticmethod
    def _parse_egress_rule(rule: dict) -> k8s.NetworkPolicyEgressRule:
        """Converts a egress rule defined as a dict into the cdk8s equivalent

        :param rule: the rule configuration as a dictionary
        :return: the same rule as a cdk8s NetworkPolicyEgressRule
        """
        peers = None
        if "to" in rule:
            peers = [
                k8s.NetworkPolicyPeer(
                    ip_block=t.get("ipBlock", None), namespace_selector=t.get("namespace_selector", None)
                )
                for t in rule["to"]
            ]

        ports = None
        if "ports" in rule:
            ports = [
                k8s.NetworkPolicyPort(port=k8s.IntOrString.from_number(p["port"]), protocol=p.get("protocol", None))
                for p in rule["ports"]
            ]

        return k8s.NetworkPolicyEgressRule(to=peers, ports=ports)

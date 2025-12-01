from dataclasses import dataclass
from enum import auto, Enum

from strenum import (  # will be default in python 3.11+
    LowercaseStrEnum,
    SnakeCaseStrEnum,
    StrEnum,
)

MAIN_NS = "kalm-benchmark"
UNRESTRICTED_NS = "kalm-benchmark-unrestricted-ns"


class CheckKey(SnakeCaseStrEnum):
    CheckId = "check"
    CheckPath = auto()
    Description = auto()
    Expect = "expected"
    Standards = auto()
    CcssScore = auto()
    CcssSeverity = auto()


CMDS = [
    "bin/bash",
    "sbin/sh",
    "bin/ksh",
    "bin/tcsh",
    "bin/zsh",
    "usr/bin/scsh",
    "bin/csh",
    "bin/busybox",
    "usr/bin/busybox",
]
SENSITIVE_KEYS = [
    "aws_access_key_id",
    "aws_secret_access_key",
    "azure_batchai_storage_account",
    "azure_batchai_storage_key",
    "azure_batch_account",
    "azure_batch_key",
    "secret",
    "key",
    "password",
    "pwd",
    "token",
    "jwt",
    "bearer",
    "credential",
]
SENSITIVE_VALUES = "PRIVATE KEY eyJhbGciO JWT Bearer"
DANGEROUS_CAPABILITIES = ["ALL", "SYS_ADMIN", "NET_ADMIN"]
INSECURE_CAPABILITIES = [
    "AUDIT_WRITE",
    "BPF",
    "CHOWN",
    "DAC_OVERRIDES",
    "FOWNER",
    "FSETID",
    "KILL",
    "MAC_OVERRIDE",
    "MAC_ADMIN",
    "MKNOD",
    "NET_BIND_SERVICE",
    "NET_RAW",
    "PERFMON",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_BOOT",
    "SYS_CHROOT",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_PTRACE",
]

class StandardsAndGuidelines(StrEnum):
    cis_benchmark = "CIS Kubernetes Benchmark"
    nsa_cisa = "NSA-CISA Kubernetes Hardening Guide"
    k8s_stig = "CIS Kubernetes STIG"
    bsi_k8s = "BSI APP.4.4 Kubernetes"
    pci_guidance = "PCI Guidance for Containers and Container Orchestration Tools"
    ms_threat_matrix = "Microsoft Threat Matrix for Kubernetes"
    k8s_checklist = "Kubernetes Security Checklist"
    owasp_k8s = "OWASP Kubernetes Security Cheat Sheet"

class StandardsFields(StrEnum):
    standard = "standard"
    version = "version"
    controls = "controls"

class CisBenchmarkVersions(StrEnum):
    v_1_12 = "1.12"

class CisBenchmarkControls(StrEnum):
    cis_1_1_1 = "1.1.1"
    cis_1_1_2 = "1.1.2"
    cis_1_1_3 = "1.1.3"
    cis_1_1_4 = "1.1.4"
    cis_1_1_5 = "1.1.5"
    cis_1_1_6 = "1.1.6"
    cis_1_1_7 = "1.1.7"
    cis_1_1_8 = "1.1.8"
    cis_1_1_9 = "1.1.9"
    cis_1_1_10 = "1.1.10"
    cis_1_1_11 = "1.1.11"
    cis_1_1_12 = "1.1.12"
    cis_1_1_13 = "1.1.13"
    cis_1_1_14 = "1.1.14"
    cis_1_1_15 = "1.1.15"
    cis_1_1_16 = "1.1.16"
    cis_1_1_17 = "1.1.17"
    cis_1_1_18 = "1.1.18"
    cis_1_1_19 = "1.1.19"
    cis_1_1_20 = "1.1.20"
    cis_1_1_21 = "1.1.21"
    cis_1_2_1 = "1.2.1"
    cis_1_2_2 = "1.2.2"
    cis_1_2_3 = "1.2.3"
    cis_1_2_4 = "1.2.4"
    cis_1_2_5 = "1.2.5"
    cis_1_2_6 = "1.2.6"
    cis_1_2_7 = "1.2.7"
    cis_1_2_8 = "1.2.8"
    cis_1_2_9 = "1.2.9"
    cis_1_2_10 = "1.2.10"
    cis_1_2_11 = "1.2.11"
    cis_1_2_12 = "1.2.12"
    cis_1_2_13 = "1.2.13"
    cis_1_2_14 = "1.2.14"
    cis_1_2_15 = "1.2.15"
    cis_1_2_16 = "1.2.16"
    cis_1_2_17 = "1.2.17"
    cis_1_2_18 = "1.2.18"
    cis_1_2_19 = "1.2.19"
    cis_1_2_20 = "1.2.20"
    cis_1_2_21 = "1.2.21"
    cis_1_2_22 = "1.2.22"
    cis_1_2_23 = "1.2.23"
    cis_1_2_24 = "1.2.24"
    cis_1_2_25 = "1.2.25"
    cis_1_2_26 = "1.2.26"
    cis_1_2_27 = "1.2.27"
    cis_1_2_28 = "1.2.28"
    cis_1_2_29 = "1.2.29"
    cis_1_2_30 = "1.2.30"
    cis_1_3_1 = "1.3.1"
    cis_1_3_2 = "1.3.2"
    cis_1_3_3 = "1.3.3"
    cis_1_3_4 = "1.3.4"
    cis_1_3_5 = "1.3.5"
    cis_1_3_6 = "1.3.6"
    cis_1_3_7 = "1.3.7"
    cis_1_4_1 = "1.4.1"
    cis_1_4_2 = "1.4.2"
    cis_2_1 = "2.1"
    cis_2_2 = "2.2"
    cis_2_3 = "2.3"
    cis_2_4 = "2.4"
    cis_2_5 = "2.5"
    cis_2_6 = "2.6"
    cis_2_7 = "2.7"
    cis_3_1_1 = "3.1.1"
    cis_3_1_2 = "3.1.2"
    cis_3_1_3 = "3.1.3"
    cis_3_2_1 = "3.2.1"
    cis_3_2_2 = "3.2.2"
    cis_4_1_1 = "4.1.1"
    cis_4_1_2 = "4.1.2"
    cis_4_1_3 = "4.1.3"
    cis_4_1_4 = "4.1.4"
    cis_4_1_5 = "4.1.5"
    cis_4_1_6 = "4.1.6"
    cis_4_1_7 = "4.1.7"
    cis_4_1_8 = "4.1.8"
    cis_4_1_9 = "4.1.9"
    cis_4_1_10 = "4.1.10"
    cis_4_2_1 = "4.2.1"
    cis_4_2_2 = "4.2.2"
    cis_4_2_3 = "4.2.3"
    cis_4_2_4 = "4.2.4"
    cis_4_2_5 = "4.2.5"
    cis_4_2_6 = "4.2.6"
    cis_4_2_7 = "4.2.7"
    cis_4_2_8 = "4.2.8"
    cis_4_2_9 = "4.2.9"
    cis_4_2_10 = "4.2.10"
    cis_4_2_11 = "4.2.11"
    cis_4_2_12 = "4.2.12"
    cis_4_2_13 = "4.2.13"
    cis_4_2_14 = "4.2.14"
    cis_4_3_1 = "4.3.1"
    cis_5_1_1 = "5.1.1"
    cis_5_1_2 = "5.1.2"
    cis_5_1_3 = "5.1.3"
    cis_5_1_4 = "5.1.4"
    cis_5_1_5 = "5.1.5"
    cis_5_1_6 = "5.1.6"
    cis_5_1_7 = "5.1.7"
    cis_5_1_8 = "5.1.8"
    cis_5_1_9 = "5.1.9"
    cis_5_1_10 = "5.1.10"
    cis_5_1_11 = "5.1.11"
    cis_5_1_12 = "5.1.12"
    cis_5_1_13 = "5.1.13"
    cis_5_2_1 = "5.2.1"
    cis_5_2_2 = "5.2.2"
    cis_5_2_3 = "5.2.3"
    cis_5_2_4 = "5.2.4"
    cis_5_2_5 = "5.2.5"
    cis_5_2_6 = "5.2.6"
    cis_5_2_7 = "5.2.7"
    cis_5_2_8 = "5.2.8"
    cis_5_2_9 = "5.2.9"
    cis_5_2_10 = "5.2.10"
    cis_5_2_11 = "5.2.11"
    cis_5_2_12 = "5.2.12"
    cis_5_3_1 = "5.3.1"
    cis_5_3_2 = "5.3.2"
    cis_5_4_1 = "5.4.1"
    cis_5_4_2 = "5.4.2"
    cis_5_5_1 = "5.5.1"
    cis_5_6_1 = "5.6.1"
    cis_5_6_2 = "5.6.2"
    cis_5_6_3 = "5.6.3"
    cis_5_6_4 = "5.6.4"

class NsaCisaControls(StrEnum):
    kubernetes_pod_security = "Kubernetes Pod Security"
    non_root_containers = "`Non-root` containers and `rootless` container engines"
    immutable_filesystem = "Immutable container file systems"
    secure_images = "Building secure container images"
    security_enforcements = "Pod security enforcement"
    service_account_tokens = "Protecting Pod service account tokens"
    hardening_container = "Hardening container environments"
    network_separation_and_hardening = "Network separation and hardening"
    namespaces = "Namespaces"
    network_policies = "Network policies"
    resource_policies = "Resource policies"
    control_plane_hardening = "Control plane hardening"
    etcd = "etcd"
    kubeconfig_files = "Kubeconfig files"
    worker_node_segmentation = "Worker node segmentation"
    encryption = "Encryption"
    secrets = "Secrets"
    sensitive_cloud_infrastructure = "Protecting sensitive cloud infrastructure"
    authentication_and_authorization = "Authentication and authorization"
    authentication = "Authentication"
    rbac = "Role-Based Access Control"
    audit_logging_and_threat_detection = "Audit logging and threat detection"
    logging = "Logging"
    native_audit_logging = "Kubernetes native audit logging configuration"
    container_logging = "Worker node and container logging"
    seccomp = "Seccomp: audit mode"
    syslog = "Syslog"
    siem_platforms = "SIEM platforms"
    service_meshes = "Service meshes"
    fault_tolerance = "Fault tolerance"
    threat_detection = "Threat detection"
    alerting = "Alerting"
    tools = "Tools"
    upgrade = "Upgrade and application security practices"

class K8sStigControls(StrEnum):
    v_242376 = "V-242376"
    v_242377 = "V-242377"
    v_242378 = "V-242378"
    v_242379 = "V-242379"
    v_242380 = "V-242380"
    v_242381 = "V-242381"
    v_242382 = "V-242382"
    v_242383 = "V-242383"
    v_242384 = "V-242384"
    v_242385 = "V-242385"
    v_242386 = "V-242386"
    v_242387 = "V-242387"
    v_242388 = "V-242388"
    v_242389 = "V-242389"
    v_242390 = "V-242390"
    v_242391 = "V-242391"
    v_242392 = "V-242392"
    v_242393 = "V-242393"
    v_242394 = "V-242394"
    v_242395 = "V-242395"
    v_242396 = "V-242396"
    v_242397 = "V-242397"
    v_242398 = "V-242398"
    v_242399 = "V-242399"
    v_242400 = "V-242400"
    v_242402 = "V-242402"
    v_242403 = "V-242403"
    v_242404 = "V-242404"
    v_242405 = "V-242405"
    v_242406 = "V-242406"
    v_242407 = "V-242407"
    v_242408 = "V-242408"
    v_242409 = "V-242409"
    v_242410 = "V-242410"
    v_242411 = "V-242411"
    v_242412 = "V-242412"
    v_242413 = "V-242413"
    v_242414 = "V-242414"
    v_242415 = "V-242415"
    v_242417 = "V-242417"
    v_242418 = "V-242418"
    v_242419 = "V-242419"
    v_242420 = "V-242420"
    v_242421 = "V-242421"
    v_242422 = "V-242422"
    v_242423 = "V-242423"
    v_242424 = "V-242424"
    v_242425 = "V-242425"
    v_242426 = "V-242426"
    v_242427 = "V-242427"
    v_242428 = "V-242428"
    v_242429 = "V-242429"
    v_242430 = "V-242430"
    v_242431 = "V-242431"
    v_242432 = "V-242432"
    v_242433 = "V-242433"
    v_242434 = "V-242434"
    v_242436 = "V-242436"
    v_242437 = "V-242437"
    v_242438 = "V-242438"
    v_242442 = "V-242442"
    v_242443 = "V-242443"
    v_242444 = "V-242444"
    v_242445 = "V-242445"
    v_242446 = "V-242446"
    v_242447 = "V-242447"
    v_242448 = "V-242448"
    v_242449 = "V-242449"
    v_242450 = "V-242450"
    v_242451 = "V-242451"
    v_242452 = "V-242452"
    v_242453 = "V-242453"
    v_242454 = "V-242454"
    v_242455 = "V-242455"
    v_242456 = "V-242456"
    v_242457 = "V-242457"
    v_242459 = "V-242459"
    v_242460 = "V-242460"
    v_242461 = "V-242461"
    v_242462 = "V-242462"
    v_242463 = "V-242463"
    v_242464 = "V-242464"
    v_242465 = "V-242465"
    v_242466 = "V-242466"
    v_242467 = "V-242467"
    v_245541 = "V-245541"
    v_245542 = "V-245542"
    v_245543 = "V-245543"
    v_245544 = "V-245544"
    v_254800 = "V-254800"
    v_254801 = "V-254801"

class BsiK8sControls(StrEnum):
    app_4_4_a1 = "APP.4.4.A1"
    app_4_4_a2 = "APP.4.4.A2"
    app_4_4_a3 = "APP.4.4.A3"
    app_4_4_a4 = "APP.4.4.A4"
    app_4_4_a5 = "APP.4.4.A5"
    app_4_4_a6 = "APP.4.4.A6"
    app_4_4_a7 = "APP.4.4.A7"
    app_4_4_a8 = "APP.4.4.A8"
    app_4_4_a9 = "APP.4.4.A9"
    app_4_4_a10 = "APP.4.4.A10"
    app_4_4_a11 = "APP.4.4.A11"
    app_4_4_a12 = "APP.4.4.A12"
    app_4_4_a13 = "APP.4.4.A13"
    app_4_4_a14 = "APP.4.4.A14"
    app_4_4_a15 = "APP.4.4.A15"
    app_4_4_a16 = "APP.4.4.A16"
    app_4_4_a17 = "APP.4.4.A17"
    app_4_4_a18 = "APP.4.4.A18"
    app_4_4_a19 = "APP.4.4.A19"
    app_4_4_a20 = "APP.4.4.A20"
    app_4_4_a21 = "APP.4.4.A21"

class PciGuidanceControls(StrEnum):
    pci_1_1_a = "1.1.a"
    pci_1_2_a = "1.2.a"
    pci_1_3_a = "1.3.a"
    pci_1_4_a = "1.4.a"
    pci_1_5_a = "1.5.a"
    pci_1_5_b = "1.5.b"
    pci_1_6_a = "1.6.a"
    pci_2_1_a = "2.1.a"
    pci_2_2_a = "2.2.a"
    pci_2_2_b = "2.2.b"
    pci_2_3_a = "2.3.a"
    pci_3_1_a = "3.1.a"
    pci_3_2_a = "3.2.a"
    pci_3_3_a = "3.3.a"
    pci_4_1_a = "4.1.a"
    pci_4_2_a = "4.2.a"
    pci_4_3_a = "4.3.a"
    pci_5_1_a = "5.1.a"
    pci_5_1_b = "5.1.b"
    pci_5_2_a = "5.2.a"
    pci_6_1_a = "6.1.a"
    pci_6_2_a = "6.2.a"
    pci_7_1_a = "7.1.a"
    pci_8_1_a = "8.1.a"
    pci_8_2_a = "8.2.a"
    pci_9_1_a = "9.1.a"
    pci_9_2_a = "9.2.a"
    pci_10_1_a = "10.1.a"
    pci_10_2_a = "10.2.a"
    pci_10_3_a = "10.3.a"
    pci_11_1_a = "11.1.a"
    pci_12_1_a = "12.1.a"
    pci_12_2_a = "12.2.a"
    pci_12_3_a = "12.3.a"
    pci_12_4_a = "12.4.a"
    pci_13_1_a = "13.1.a"
    pci_13_1_b = "13.1.b"
    pci_13_2_a = "13.2.a"
    pci_13_3_a = "13.3.a"
    pci_13_4_a = "13.4.a"
    pci_14_1_a = "14.1.a"
    pci_14_1_b = "14.1.b"
    pci_14_1_c = "14.1.c"
    pci_15_1_a = "15.1.a"
    pci_15_1_b = "15.1.b"
    pci_16_1_a = "16.1.a"
    pci_16_2_a = "16.2.a"
    pci_16_3_a = "16.3.a"
    pci_16_4_a = "16.4.a"

class MsThreatMatrixControls(StrEnum):
    ms_m9001 = "MS-M9001"
    ms_m9002 = "MS-M9002"
    ms_m9003 = "MS-M9003"
    ms_m9004 = "MS-M9004"
    ms_m9005 = "MS-M9005"
    ms_m9005_001 = "MS-M9005.001"
    ms_m9005_002 = "MS-M9005.002"
    ms_m9005_003 = "MS-M9005.003"
    ms_m9006 = "MS-M9006"
    ms_m9007 = "MS-M9007"
    ms_m9008 = "MS-M9008"
    ms_m9009 = "MS-M9009"
    ms_m9010 = "MS-M9010"
    ms_m9011 = "MS-M9011"
    ms_m9012 = "MS-M9012"
    ms_m9013 = "MS-M9013"
    ms_m9014 = "MS-M9014"
    ms_m9015 = "MS-M9015"
    ms_m9016 = "MS-M9016"
    ms_m9017 = "MS-M9017"
    ms_m9018 = "MS-M9018"
    ms_m9019 = "MS-M9019"
    ms_m9020 = "MS-M9020"
    ms_m9021 = "MS-M9021"
    ms_m9022 = "MS-M9022"
    ms_m9023 = "MS-M9023"
    ms_m9024 = "MS-M9024"
    ms_m9025 = "MS-M9025"
    ms_m9026 = "MS-M9026"
    ms_m9027 = "MS-M9027"
    ms_m9028 = "MS-M9028"
    ms_m9029 = "MS-M9029"
    ms_m9030 = "MS-M9030"
    ms_m9031 = "MS-M9031"
    ms_m9032 = "MS-M9032"

class K8sChecklistControls(StrEnum):
    sc_aa_system_masters = "system:masters group is not used for user or component authentication after bootstrapping"
    sc_aa_kube_controller_manager = "The kube-controller-manager is running with --use-service-account-credentials enabled."
    sc_aa_root_certificate = "The root certificate is protected (either an offlineCA, or a managed online CA with effective access controls)."
    sc_aa_intermediate_certificate = "Intermediate and leaf certificates have an expiry date no more than 3 years in the future."
    sc_aa_access_review = "A process exists for periodic access review, and reviews occur no more than 24 months apart."
    sc_aa_rbac = "The Role Based Access Control Practices are followed for guidance related to authentication and authorization."
    sc_ns_cni_plugins = "CNI plugins in use support network policies."
    sc_ns_ingress_egress = "Ingress and egress network policies are applied to all workloads in the cluster."
    sc_ns_default_network_policies = "Default network policies within each namespace, selecting all pods, denying everything, are in place."
    sc_ns_service_mesh = "If appropriate, a service mesh is used to encrypt all communications inside of the cluster."
    sc_ns_cloud_metadata = "Access from the workloads to the cloud metadata API is filtered."
    sc_ns_load_balancers = "Use of LoadBalancer and ExternalIPs is restricted."
    sc_ns_etcd_datastore = "etcd datastore of the control plane should have controls to limit access and not be publicly exposed on the Internet."
    sc_ns_mutual_tls = "mutual TLS (mTLS) should be used to communicate securely with etcd."
    sc_ns_ca_etcd = "certificate authority for etcd should be unique"
    sc_ns_no_public_api = "External Internet access to the Kubernetes API server should be restricted to not expose the API publicly."
    sc_ps_rbac = "RBAC rights to create, update, patch, delete workloads is only granted if necessary."
    sc_ps_security_standards_policy = "Appropriate Pod Security Standards policy is applied for all namespaces and enforced."
    sc_ps_memory_limit = "Memory limit is set for the workloads with a limit equal or inferior to the request."
    sc_ps_cpu_limit = "CPU limit might be set on sensitive workloads."
    sc_ps_seccomp = "For nodes that support it, Seccomp is enabled with appropriate syscalls profile for programs."
    sc_ps_apparmor = "For nodes that support it, AppArmor or SELinux is enabled with appropriate profile for programs."
    sc_la_audit_logs = "Audit logs, if enabled, are protected from general access."
    sc_pp_pod_placement = "Pod placement is done in accordance with the tiers of sensitivity of the application."
    sc_pp_isolated = "Sensitive applications are running isolated on nodes or with specific sandboxed runtimes."
    sc_se_config_maps = "ConfigMaps are not used to hold confidential data."
    sc_se_encryption = "Encryption at rest is configured for the Secret API."
    sc_se_third_party_storage = "If appropriate, a mechanism to inject secrets stored in third-party storage is deployed and available."
    sc_se_service_account_tokens = "Service account tokens are not mounted in pods that don`t require them."
    sc_se_non_expiring_tokens = "Bound service account token volume is in-use instead of non-expiring tokens."
    sc_se_mounted_volumes = "Pods needing secrets should have these automatically mounted through volumes, preferably stored in memory like with the emtpyDir.medium option."
    sc_im_minimize_contents = "Minimize unnecessary content in container images."
    sc_im_unprivileged_user = "Container images are configured to be run as an unprivileged user."
    sc_im_sha256_digest = "References to container images are made by sha256 digests (rather than tags) or the provenance of the image is validated by verifying the image`s digital signature at deploy time via admission control."
    sc_im_regular_scan = "Container images are regularly scanned during creation and in deployment, and known vulnerable software is patched."
    sc_im_no_shells = "images used in production should not contain shells or debugging utilties."
    sc_im_start_unprivileged = "Build images to directly start with unprivileged user."
    sc_im_security_context = "The Security Context allows a container image to be started with a specific user and group with runAsUser and runAsGroup, even if not specified in the image manifest."
    sc_ac_selection_enabled = "An appropriate selection of admission controllers is enabled."
    sc_ac_policy_enforced = "A pod security policy is enforced by the Pod Security Admission or/and a webhook admission controller."
    sc_ac_chain_plugins = "The admission chain plugins and webhooks are securely configured."
    sc_ac_certificate_approval = "CertificateApproval - Performs additional authorization checks to ensure the approving user has permission to approve certificate requests."
    sc_ac_certificate_signing = "CertificateSigning - Performs additional authorization checks to ensure the signing user has permission to sign certificate requests."
    sc_ac_certificate_subject_restriction = "CertificateSubjectRestriction - Rejects any certificate request that specifies a `group` (or `organization attribute`) of system:masters."
    sc_ac_limit_ranger = "LimitRanger - Enforces the LimitRange API constraints."
    sc_ac_mutating_admission_webhook = "MutatingAdmissionWebhook - Allows the use of custom controllers through webhooks, these controllers may mutate requests that they review."
    sc_ac_pod_security = "PodSecurity - Replacement for Pod Security Policy, restricts security contexts of deployed Pods."
    sc_ac_resource_quote = "ResourceQuota - Enforces resource quotas to prevent over-usage of resources."
    sc_ac_validating_admission_webhook = "ValidatingAdmissionWebhook - Allows the use of custom controllers through webhooks, these controllers may accept or reject requests that it reviews."
    sc_ac_deny_service_external_ip = "DenyServiceExternalIPs - Rejects all net-new usage of the Service.spec.externalIPs field. This is a mitigation for CVE-2020-8554: Man in the middle using LoadBalancer or ExternalIPs."
    sc_ac_node_restriction = "NodeRestriction - Restricts kubelet`s permissions to only modify the pods API resources they own or the node API resource that represent themselves."
    sc_ac_always_pull_images = "AlwaysPullImages - Enforces the usage of the latest version of a tagged image and ensures that the deployer has permissions to use the image."
    sc_ac_image_policy_webhook = "ImagePolicyWebhook - Allows enforcing additional controls for images through webhooks."
    asc_ad_security_principles = "Follow the right security principles when designing applications."
    asc_ad_memory_limit = "Memory limit is set for the workloads with a limit equal to or greater than the request."
    asc_ad_cpu_limit = "CPU limit might be set on sensitive workloads."
    asc_sa_service_account = "Avoid using the default ServiceAccount. Instead, create ServiceAccounts for each workload or microservice."
    asc_sa_service_account_token = "automountServiceAccountToken should be set to false unless the pod specifically requires access to the Kubernetes API to operate."
    asc_pl_run_as_non_root = "Set runAsNonRoot: true"
    asc_pl_less_privileged = "Configure the container to execute as a less privileged user (for example, using runAsUser and runAsGroup), and configure appropriate permissions on files or directories inside the container image."
    asc_pl_fs_group = "Optionally add a supplementary group with fsGroup to access persistent volumes."
    asc_pl_namespace = "The application deploys into a namespace that enforces an appropriate Pod security standard."
    asc_cl_allow_privilege_escalation = "Disable privilege escalations using allowPrivilegeEscalation: false."
    asc_cl_read_only_root_filesystem = "Configure the root filesystem to be read-only with readOnlyRootFilesystem: true."
    asc_cl_privileged_false = "Avoid running privileged containers (set privileged: false)."
    asc_cl_drop_capabilities = "Drop all capabilities from the containers and add back only specific ones that are needed for operation of the container."
    asc_rbac_permissions_if_necessary = "Permissions such as create, patch, update and delete should be only granted if necessary."
    asc_rbac_privilege_escalation = "Avoid creating RBAC permissions to create or update roles which can lead to privilege escalation."
    asc_rbac_review_bindings = "Review bindings for the system:unauthenticated group and remove them where possible, as this gives access to anyone who can contact the API server at a network level."
    asc_is_scanning_tool = "Using an image scanning tool to scan an image before deploying containers in the Kubernetes cluster."
    asc_is_container_signing = "Use container signing to validate the container image signature before deploying to the Kubernetes cluster."
    asc_ns_network_policies = "Configure NetworkPolicies to only allow expected ingress and egress traffic from the pods."
    asc_lcs_seccomp = "Set the Seccomp Profile for a Container"
    asc_lcs_apparmor = "Restrict a Container`s Access to Resources with AppArmor"
    asc_lcs_selinux = "Assign SELinux Labels to a Container"
    asc_rc_runtime_classes = "Configure appropriate runtime classes for containers"

class OwaspControls(StrEnum):
    s1_updating_kubernetes = "Updating Kubernetes"
    s2_securing_dashboard = "Securing the Kubernetes Dashboard"
    s2_restricting_access = "Restricting access to etcd"
    s2_limiting_access = "Limiting access to the primary etcd instance"
    s2_sensitive_ports = "Controlling network access to sensitive ports"
    s2_kubernetes_api = "Controlling access to the Kubernetes API"
    s2_api_authorization = "How Kubernetes handles API authorization"
    s2_api_authentication = "External API Authentication for Kubernetes"
    s2_builtin_authentication = "Options for Kubernetes built-in API authentication"
    s2_rbac = "Implementing Role Based Access Control in Kubernetes"
    s2_access_kubelets = "Limiting access to the Kubelets"
    s3_container_image = "What is a container image"
    s3_ci_update = "Ensure that CIs are up to date"
    s3_authorized_images = "Only use authorized images in your environment"
    s3_ci_pipeline = "Use a CI pipeline to control and identify vulnerabilities"
    s3_minimize_features = "Minimize features in all CIs"
    s3_distroless_images = "Use distroless or empty images when possible"
    s4_namespace_isolation = "Code that uses namespaces to isolate Kubernetes resources"
    s4_image_policy_webhook = "Use the ImagePolicyWebhook to govern image provenance"
    s4_continuous_scanning = "Implement continuous security vulnerability scanning"
    s4_security_context = "Apply security context to your pods and containers"
    s4_security_context_example = "Security context example: A pod definition that include security context parameters"
    s4_continously_assess = "Continuously assess the privileges used in containers"
    s4_pod_security_standards = "Utilize Pod Security Standards and the Built-in Pod Security Admission Controller to enforce container privilege levels"
    s4_pod_security_policies = "Use Pod security policies to control the security-related attributes of pods, which includes container privilege levels"
    s4_extra_security = "Providing extra security with a service mesh"
    s4_advantages_service_mesh = "Advantages of a service mesh"
    s4_disadvantages_service_mesh = "Disadvantages of the security mesh"
    s4_policy_managed = "Implementing centralized policy management"
    s4_opa = "Most common use cases of OPA"
    s4_limiting_resource = "Limiting resource usage on a cluster"
    s4_network_policies = "Use Kubernetes network policies to control traffic between pods and clusters"
    s4_securing_data = "Securing data"
    s4_keep_secrets = "Keep secrets a secret"
    s4_encrypt_secrets = "Encrypt secrets at rest"
    s4_alternatives_to_k8s_secrets = "Alternatives to Kubernetes Secret resources"
    s4_finding_secrets = "Finding exposed secrets"
    s5_pod_security_admission = "Use Pod Security Admission to prevent risky containers / pods from being deployed"
    s5_runtime_security = "Container runtime security"
    s5_container_sandboxing = "Container sandboxing"
    s5_unwanted_kernel_modules = "Prevent containers from loading unwanted kernel modules"
    s5_runtime_activity = "Compare and analyze different runtime activity in pods of the same deployments"
    s5_network_traffic = "Monitor network traffic to limit unnecessary or insecure communication"
    s5_scale_suspicious_pods = "If breached, scale suspicious pods to zero"
    s5_rotate_credentials = "Rotate infrastructure credentials frequently"
    s5_logging = "Logging"
    s5_audit_logging = "Enable audit logging"
    s5_audit_policies = "Define audit policies"
    s5_understand_logging = "Understand logging"
    s5_events = "Events"
    s6_aws = "AWS"
    s7_embed_security = "Embed security into the container lifecycle as early as possible"
    s7_security_controls = "Use Kubernetes-native security controls to reduce operational risk"
    s7_leverage_context = "Leverage the context that Kubernetes provides to prioritize remediation efforts"

class PodSecurityLevel(LowercaseStrEnum):
    Privileged = auto()
    Baseline = auto()
    Restricted = auto()


class PodSecurityAdmissionMode(LowercaseStrEnum):
    Warn = auto()
    Audit = auto()
    Enforce = auto()


class AppArmorProfile(StrEnum):
    # https://kubernetes.io/docs/tutorials/security/apparmor/#podsecuritypolicy-annotations
    Unconfined = "unconfined"  # disables AppArmor
    RuntimeDefault = "runtime/default"
    localhost = "localhost/"  # requires path to local profile after the slash


class SeccompProfile(StrEnum):
    Unconfined = "Unconfined"  # disables Seccomp
    RuntimeDefault = "RuntimeDefault"
    localhost = "Localhost/"  # requires path to local profile after the slash


class SeccompProfileForPSP(StrEnum):
    # name of same profile differ for PSP and pod itself
    Unconfined = "unconfined"  # disables Seccomp
    RuntimeDefault = "runtime/default"
    DockerDefault = "docker/default"  # docker/default is deprecated as of 1.11
    localhost = "localhost/"  # requires path to local profile after the slash


class SeLinuxRule(StrEnum):
    MustRunAs = "MustRunAs"  # Requires at least one range to be specified. Uses the minimum value
    # of the first range as the default. Validates against all ranges.
    RunAsAny = "RunAsAny"  # No default provided. Allows any fsGroup ID to be specified.


class GenericPspRule(StrEnum):
    MustRunAs = "MustRunAs"  # Requires at least one range to be specified. Uses the minimum value
    # of the first range as the default. Validates against all ranges.
    MayRunAs = "MayRunAs"  # Requires at least one range to be specified. Allows FSGroups to be left
    # unset without providing a default. Validates against all ranges if FSGroups is set.
    RunAsAny = "RunAsAny"  # No default provided. Allows any fsGroup ID to be specified.


class FsGroupRule(StrEnum):
    MustRunAs = "MustRunAs"  # Requires at least one range to be specified. Uses the minimum value
    # of the first range as the default. Validates against all ranges.
    MayRunAs = "MayRunAs"  # Requires at least one range to be specified. Allows FSGroups to be left
    # unset without providing a default. Validates against all ranges if FSGroups is set.
    RunAsAny = "RunAsAny"  # No default provided. Allows any fsGroup ID to be specified.


class RunAsUserRule(StrEnum):
    MustRunAsNonRoot = "MustRunAsNonRoot"
    MustRunAs = "MustRunAs"
    RunAsAny = "RunAsAny"


class SupplementalGroupsRule(StrEnum):
    MustRunAs = "MustRunAs"  # Requires at least one range to be specified. Uses the minimum value
    # of the first range as the default. Validates against all ranges.
    MayRunAs = "MayRunAs"  # Requires at least one range to be specified. Allows supplementalGroups to be left
    # unset without providing a default. Validates against all ranges if supplementalGroups is set.
    RunAsAny = "RunAsAny"  # No default provided. Allows any SupplementalGroup ID to be specified.


class CheckStatus(StrEnum):
    Pass = "pass"
    Alert = "alert"


class VolumeType(StrEnum):
    Empty = "empty"
    HostPath = "hostpath"


@dataclass
class MissingCheck:
    id: str
    name: str
    description: str
    checked_path: str | None = None
    expected: str | None = "alert"


@dataclass
class ResourceQuotaConfig:
    """Configuration for ResourceQuota settings"""

    enabled: bool = True
    kwargs: dict | None = None

    def __post_init__(self):
        if self.kwargs is None:
            self.kwargs = {}


@dataclass
class LimitRangeConfig:
    """Configuration for LimitRange settings"""

    enabled: bool = True
    kwargs: dict | None = None

    def __post_init__(self):
        if self.kwargs is None:
            self.kwargs = {}


@dataclass
class NetworkPolicyConfig:
    """Configuration for NetworkPolicy settings"""

    enabled: bool = True
    kwargs: dict | None = None

    def __post_init__(self):
        if self.kwargs is None:
            self.kwargs = {}


@dataclass
class SubjectConfig:
    """Configuration for RBAC Subject settings"""

    name: str | None = None
    type: str | None = None  # Using str to avoid circular import

    def __post_init__(self):
        # Import here to avoid circular dependency
        from .rbac import SubjectType

        if self.name and not self.type:
            self.type = SubjectType.SA


@dataclass
class RoleConfig:
    """Configuration for RBAC Role settings"""

    name: str | list[str] | None = None
    exists: bool = False
    is_cluster_role: bool = False
    resources: list[str] | str | None = None
    verbs: list[str] | str | None = None
    api_groups: list[str] | str | None = None

    def __post_init__(self):
        if self.name is None:
            self.name = []


@dataclass
class RBACBindingConfig:
    """Configuration for RBAC Binding settings"""

    is_cluster_binding: bool = False


@dataclass
class ContainerResourceConfig:
    """Configuration for container resource requests and limits"""

    request_cpu: str | None = "1m"
    limits_cpu: str | None = "1m"
    request_memory: str | None = "1Mi"
    limits_memory: str | None = "1Mi"
    request_ephemeral_storage: str | None = "1Mi"
    limits_ephemeral_storage: str | None = "1Mi"


@dataclass
class ContainerConfig:
    """Configuration for container settings"""

    image: str = "nginx"
    image_tag: str | None = "@sha256:aed492c4dc93d2d1f6fe9a49f00bc7e1863d950334a93facd8ca1317292bf6aa"
    image_pull_policy: str | None = "Always"
    container_port: int = 8080
    host_port: int | None = None
    env_vars: list | None = None
    security_context: dict | bool | None = True
    security_context_kwargs: dict | None = None
    resources: ContainerResourceConfig | None = None

    def __post_init__(self):
        if self.resources is None:
            self.resources = ContainerResourceConfig()
        if self.env_vars is None:
            self.env_vars = []


@dataclass
class PodSecurityConfig:
    """Configuration for pod security settings"""

    service_account_name: str | None = "<POD>-dedicated-sa"
    service_account: str | None = None
    automount_sa_token: bool | None = False
    host_ipc: bool | None = False
    host_pid: bool | None = False
    host_network: bool | None = False
    pod_security_context: dict | bool | None = True
    pod_security_context_kwargs: dict | None = None

    def __post_init__(self):
        if self.pod_security_context_kwargs is None:
            self.pod_security_context_kwargs = {}


@dataclass
class PodSchedulingConfig:
    """Configuration for pod scheduling settings"""

    node_selector: dict | None = None
    node_affinity: dict | bool | None = None
    priority_class: str | None = "default-priority"

    def __post_init__(self):
        if self.node_selector is None:
            self.node_selector = {"kubernetes.io/arch": "amd64"}


@dataclass
class Ccss:
    """ Common Configuration Scoring System """

    base_score: float = 0.0
    severity: str = "None"


MISSING_CHECKS = [
    MissingCheck(
        "RBAC-011",
        "minimize subjects per namespace",
        "Significant number of Subjects having access to a Namespace might be a potential security risk",
    ),
    MissingCheck(
        "RBAC-018",
        "Role that grant permissions to system reserved namespace",
        "A role was found that grants permission over system reserved namespace (either default or kube-system)",
    ),
    MissingCheck(
        "RBAC-019",
        "Avoid use of system:masters group",
        (
            "The system:masters group has unrestricted access to the Kubernetes API hard-coded into "
            "the API server source code. An authenticated user who is a member of this group cannot "
            "have their access reduced, even if all bindings and cluster role bindings which mention it, are removed."
        ),
        "ClusterRole.rules[].verbs|Role.rules[].verbs",
    ),
    MissingCheck("POD-004", "dont share service account between workloads", "", ".spec.serviceAccountName"),
    MissingCheck(
        "POD-005", "don't reference non-existing SA", "", ".spec.serviceAccountName|ServiceAccount.metadata.name"
    ),
    MissingCheck(
        "POD-020",
        "fsGroup / supplementalGroups should be non-zero",
        "",
        ".spec.securityContext.fsGroup|.spec.securityContext.supplementalGroups[]",
    ),
    MissingCheck(
        "POD-026",
        "Check SSH server running inside container",
        (
            "SSH server that is running inside a container may be used by attackers. "
            "If attackers gain valid credentials to a container, whether by brute force attempts "
            "or by other methods (such as phishing), they can use it to get remote access to the container by SSH."
        ),
        ".spec.containers[].ports[].containerPort",
    ),
    MissingCheck(
        "POD-026",
        "dont map privileged port into container",
        "",
        ".spec.containers[].ports.containerPort",  #
    ),
    MissingCheck(
        "POD-027",
        "Container is running with multiple open ports",
        "Having too many open ports increases the attack surface of the application and the container",
        ".spec.containers[].ports[].containerPort",
    ),
    MissingCheck(
        "POD-028",
        "don't use unsafe proc mounts",
        "",
        ".spec.containers[].securityContext.procMount",
    ),
    MissingCheck(
        "POD-047",
        "Container is running with shared mount propagation",
        "Shared volumes can overwrite data on the host, and are considered dangerous.",
        ".spec.containers[].volumeMounts[].mountPropagation",
    ),
    MissingCheck(
        "POD-048",
        "dont use disallowed volume types",
        "usage of non-ephemeral volume-types should be limited to those defined through PersistentVolumes",
        ".spec.volumes[]",
    ),
    MissingCheck(
        "NS-003",
        "ensure that components in a Namespace are restricted to only the necessary",
        (
            "Limiting the scope of user permissions can reduce the impact of mistakes or malicious activities. "
            "A Kubernetes namespace allows you to partition created resources into logically named groups. "
        ),
        ".metadata.namespace",
    ),
    MissingCheck(
        "NS-004",
        "No owner for namespace affects the operations",
        ("Limiting the scope of user permissions can reduce the impact of mistakes or malicious activities. "),
        ".metadata.namespace",
    ),
    MissingCheck(
        "CM-002",
        "Prevent ConfigMap security vulnerability (CVE-2021-25742)",
        (
            "users with limited access to a Kubernetes cluster, but with the ability to create an "
            "Ingress object based on the NGINX Ingress Controller, could elevate privilege and access "
            "full cluster secrets (NVD severity of this issue: High)."
        ),
        "Configmap.data.allow-snippet-annotation",
    ),
    MissingCheck(
        "NP-006",
        "ensure all workloads are referenced by a Network Policy",
        "",
        (
            "NetworkPolicy.spec.podSelector.matchLabels|"
            "NetworkPolicy.ingress[].from[].podSelector|"
            "NetworkPolicy.egress[].from[].podSelector"
        ),
    ),
    MissingCheck("SRV-001", "ensure all services target a pod", "", "Service.spec.selector"),
    MissingCheck(
        "SRV-002",
        "don’t use NodePort",
        (
            "NodePort services should be avoided as they are insecure, and can't be used together with NetworkPolicies."
            "Exposing a NodePort will open a port on all nodes to be reached by the cluster's external network. "
            "Using this method to expose the application is less secure and forces you to create unnecessary coupling "
            "between services in order to expose them all to external traffic."
        ),
        "Service.spec.type|Service.spec.ports[].nodePort",
    ),
    MissingCheck(
        "SC-003",
        "configure image provenance using ImagePolicyWebhook admission controller",
        "As suggested by CIS benchmark (5.5.1)",
    ),
    MissingCheck(
        "SC-004",
        "Use trusted image registry",
        "Use trusted repo which scans images for known vulnerabilities and misconfigurations",
    ),
    MissingCheck(
        "ING-001",
        "Set HTTP security headers on the Kubernetes Ingress controller",
        "",
        (
            'Ingress.metadata.annotations["nginx.ingress.kubernetes.io/configuration-snippet"]|'
            'ConfigMap.data["proxy-set-headers"]'
        ),
    ),
    MissingCheck(
        "ING-002",
        "enable TLS for Ingress",
        "Configure tls in ingress. specifying a Secret that contains a TLS private key and certificate",
        'Ingress.spec.tls|Secret.data["tls.crt"]|Secret.data["tls.key"]',
    ),
    MissingCheck(
        "ING-003",
        "ensure ingress targets a Service",
        "",
        "Ingress.spec.rules[].paths[].backend.service",
    ),
    MissingCheck(
        "ING-004",
        "prevent ingress from forwarding all traffic to a single container",
        (
            "Misconfiguring the ingress host can unintended forward all traffic to a single pod "
            "instead of leveraging the load balancing capabilities. By verifying that ingress traffic is "
            "targeted by multiple pods, you will achieve higher application availability because you won't be "
            "dependent upon a single pod to serve all ingress traffic. "
            "(Originally from Datree documentation)"
        ),
        "Ingress.spec.rules[].host",
    ),
    MissingCheck(
        "ING-005",
        "CVE-2021-25742 nginx-ingress snippet annotation vulnerability",
        (
            "Security issue in ingress-nginx where a user that can create or update ingress objects "
            "can use the custom snippets feature to obtain all secrets in the cluster "
            "(see more at https://github.com/kubernetes/ingress-nginx/issues/7837) To mitigate this vulnerability"
            "Set allow-snippet-annotations to false in your ingress-nginx ConfigMap"
        ),
        'Ingress.metadata.annotations["nginx.ingress.kubernetes.io/server-snippet"]',
    ),
]

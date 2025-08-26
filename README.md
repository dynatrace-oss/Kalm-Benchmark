<!-- markdownlint-disable MD040 MD059 -->
# 📊 Kalm Benchmark

KALM provides a **comprehensive, standardized benchmark** for evaluating and comparing Kubernetes security scanners. The benchmark consists of two components:

- **235+ intentionally vulnerable Kubernetes manifests** covering 12 major security categories that scanners should detect
- **Interactive web UI** for analyzing scanner performance, accuracy, and coverage with CCSS alignment scoring

| ⚠️ This product is not officially supported by Dynatrace. |
| --------------------------------------------------------- |

## Description

### Benchmark Manifests

KALM provides a comprehensive test suite of **235+ Kubernetes manifests** specifically designed to evaluate security scanner effectiveness. Each manifest represents a **specific security misconfiguration or vulnerability pattern** that scanners should detect.

**Key characteristics of the benchmark manifests:**

- **Intentionally vulnerable**: Each manifest contains a specific security issue (privileged containers, exposed secrets, RBAC misconfigurations, etc.)
- **Single-issue focus**: One manifest tests one security check to enable precise scanner comparison  
- **Comprehensive coverage**: Tests span **12 major security categories**:
  - **Pod Security**: Privilege escalation, host access, security contexts
  - **RBAC**: Excessive permissions, cluster-admin usage, service account issues  
  - **Network Policies**: Traffic isolation, metadata API access
  - **Resource Management**: CPU/memory limits, resource quotas
  - **Container Security**: Image policies, capabilities, read-only filesystems
  - **Secrets & ConfigMaps**: Sensitive data exposure
  - **Namespaces**: Default namespace usage, system namespace access
  - **Pod Security Standards**: PSA configuration issues
  - **Supply Chain**: Image tags, registry security
  - **Workload Types**: Naked pods, reliability configurations
  - **Network Security**: Ingress configurations, TLS settings
  - **Infrastructure**: Storage, reliability, node selection

**Structured for evaluation**: Each manifest includes metadata annotations specifying:

- Expected scanner result (`alert` or `pass`)  
- Check description and security impact
- Specific configuration paths that should be flagged
- Unique check IDs for result correlation

This design enables **precise measurement** of scanner accuracy, false positive rates, and coverage across different security domains.

📋 **Complete catalog**: [Benchmark Checks](./docs/benchmark-checks.md) (235+ individual security tests)

### Web UI

The web application consists of three pages:

- an overview of various scanners checked with this benchmark  
   ![overview](docs/images/overview_page.png)
- an analysis page to inspect the results of a specific scanner in more detail  
   ![analysis](docs/images/analysis_page.png)
- a CCSS alignment page to compare scanner performance against standardized scoring

**Recent UI Updates:**

- Settings panel with better organization and visual structure
- Logging system with centralized log management
- Automatic result saving to data directory after scans
- Real-time scan progress monitoring
- Session state management

### CCSS Integration

The benchmark now includes CCSS (Common Configuration Scoring System) integration for scanner analysis:

- **Scanner Alignment Analysis**: Compare how different scanners align with standardized CCSS scores
- **Multi-Source Support**: Evaluate scanners against Kubernetes manifests, live API servers, and Helm charts
- **Research Capabilities**: Designed to support large-scale evaluation (e.g., top 100+ Helm charts from Artifactory)
- **Flexible Configuration**: Supports any number of charts, mixed source types, and custom evaluation criteria
- **Data Models**: Extended data structures for comprehensive misconfiguration analysis

Key features:

- Interactive alignment visualizations and scanner rankings
- Category-specific performance analysis
- Statistical correlation between native scanner scores and CCSS scores
- Database persistence for evaluation runs and findings
- Backward compatibility with existing KALM functionality

## Use Cases

### **For Security and DevOps Teams:**

- **Scanner Evaluation**: Compare 12+ security scanners across 235+ real-world vulnerability patterns
- **Tool Selection**: Identify scanners with best coverage for your specific security requirements
- **Custom Rule Development**: Use benchmark results to develop and validate custom security policies
- **Compliance Assessment**: Evaluate scanner alignment with industry standards (CCSS scoring)
- **Performance Benchmarking**: Measure scanner accuracy, false positive rates, and detection coverage

### **For Scanner Developers & Vendors:**

- **Competitive Analysis**: Compare your tool against market alternatives using standardized tests
- **Quality Assurance**: Identify detection gaps, false positives, and rule conflicts across security categories
- **Product Development**: Use benchmark feedback to improve check accuracy and coverage
- **Standards Alignment**: Optimize scanner output to align with CCSS and industry scoring standards
- **Regression Testing**: Validate that updates don't break existing detection capabilities

### **For Security Researchers & Analysts:**

- **Academic Research**: Generate publication-ready data on scanner effectiveness and accuracy trends
- **Market Analysis**: Analyze detection consistency across different security scanning solutions
- **Standards Development**: Contribute to security scanning methodology and scoring improvements
- **Large-Scale Studies**: Evaluate scanner performance across diverse Kubernetes security scenarios

## Prerequisites

- Python >= 3.9
- The manifests are generated using [cdk8s](https://cdk8s.io/), which depends on **[nodeJS](https://nodejs.org/en/)**
  - Please ensure **nodeJS** is installed on your system
- Any **scanner** for which a scan should be triggered must be installed manually
  - **📖 See the comprehensive [Scanner Installation Guide](./docs/scanner_installation.md) for detailed setup instructions**
- [Poetry](https://python-poetry.org) is used to manage the project itself

## Getting Started

### 1) 🔨 Installation

To install the benchmark along with its dependencies listed in the `pyproject.toml` execute:

```shell
poetry install
```

### 2) 🏄‍♀️ Usage

To use this package run the CLI with the appropriate command:

```shell
poetry run cli <command>
```

For detailed information of the available commands or general help run:

```shell
poetry run cli --help
```

#### 2.1) Generating manifests

To generate manifests use the `generate` command:

```shell
poetry run cli generate [--out <target directory>]
```

These manifests form the basis for the benchmark and will be placed in the directory specified with the `--out` argument. The location defaults to the `manifests` folder in the working directory.

#### 2.2) Start the Web UI

Besides the CLI commands the tool also provides a web user interface to manage the scan(s) and analyse evaluation results. It can be started with the command:

```shell
poetry run cli serve
```

The web UI includes:

- **Settings Panel**: Configure data directory and display options
- **Automatic Result Saving**: Scan results are automatically saved to unified database
- **Centralized Logging**: View scan logs and UI activity in organized log files
- **Real-time Updates**: Monitor scan progress with live status updates
- **Database Backend**: SQLite-based data storage

#### 2.3) Perform a scan with a Scanner

To scan either a cluster or manifest files with the specified tool use the `scan` command.
Use either the `-c` flag to specify the target cluster or the `-f` flag to specify the target file/folder.  

```shell
poetry run cli scan <tool> [-c | -f <target file or folder>]
```

❗️ **Important** executing a scan requires the respective tool to be installed on the system!

**📋 Supported Scanners**: Kubescape, KubeLinter, KICS, Trivy, Checkov, Polaris, Terrascan, Kube-score, Snyk, Kubesec, Kube-bench, KubiScan

**🔧 Quick Setup**: For detailed installation instructions for all scanners, see the [Scanner Installation Guide](./docs/scanner_installation.md)

E.g., to scan manifests with the tool `dummy` located in the `manifests` folder execute:

```shell
poetry run cli scan dummy -f manifests
```

In order to save the results, add the `-o` flag with the name of the destination folder:

```shell
poetry run cli scan <tool> [-c | -f <target file or folder>] -o <output-folder>
```

#### 2.4) Evaluate a Scanner

To evaluate a scanner, first run a scan to generate results in the database, then use the evaluate command:

```shell
poetry run cli evaluate <tool>
```

You can also evaluate a specific scan run:

```shell
poetry run cli evaluate <tool> --run-id <scan_run_id>
```

#### 2.5) Database Management

The benchmark uses a unified SQLite database for CCSS integration:

**View database statistics:**

```shell
poetry run cli db-stats
```

## 🚀 Deployment

Some scanners only scan resources deployed in a Kubernetes cluster.
You can find instructions on how to deploy the benchmark in a cluster [here](./docs/deployment.md)

### Scanner Requirements Summary

| Scanner Type | Requirements | Examples |
|--------------|-------------|----------|
| **Manifest-based** | Scanner binary + YAML files | Kubescape, KICS, Trivy, Polaris |
| **Cluster-based** | Scanner binary + Running K8s cluster | Kube-bench, KubiScan |
| **API Key required** | Scanner binary + External service token | Snyk, Checkov (for full features) |

📖 **Detailed setup instructions**: [Scanner Installation Guide](./docs/scanner_installation.md)

## Scanner Features & Severity Support

KALM supports **12 security scanners** and provides comprehensive severity information extraction from all of them. Each scanner has different severity formats and coverage levels.

**📊 Complete severity support matrix**: [Scanner Installation Guide - Scanner Coverage](./docs/scanner_installation.md#scanner-compatibility-matrix)

## Tool-specific considerations

Some scanners have special requirements or focus areas:

- **kube-bench**: Focuses on infrastructure security (CIS Kubernetes Benchmark) rather than workload security
- **KubiScan**: Requires special setup as it's distributed as a Python script
- **Snyk/Checkov**: Require API keys for full functionality

**📖 Complete scanner details and setup instructions**: [Scanner Installation Guide](./docs/scanner_installation.md)

## Troubleshooting

### Scanner Issues

For comprehensive troubleshooting of scanner installation, configuration, and execution issues, see the **[Scanner Installation Guide - Troubleshooting Section](./docs/scanner_installation.md#troubleshooting)**.

### Docker-based Issues

- ensure the `-t` flag is not used in the command. If it is, `stdout` and `stderr` are joined to just `stdout`. This means errors can't be handled properly and it corrupts the results in `stdout`.

## 💪 Contributing

Want to contribute? Awesome! We welcome contributions of all kinds: new scanners, fixes to the existing implementations, bug reports, and feedback of any kind.

- See the contributing guide [here](./CONTRIBUTING.md).
- Guidelines on how to onboard a new scanner can be found in the [Scanner Onboarding Guide](./docs/scanner_onboarding_guide.md)
- Check out the [Development Guide](./docs/dev_guide.md) for more information.
- By contributing you agree to abide by the [Code of Conduct](./CODE_OF_CONDUCT.md).

---

## License

[Apache Version 2.0](./LICENSE)

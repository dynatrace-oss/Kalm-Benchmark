<!-- markdownlint-disable MD024-->
# Scanner Installation Guide

This guide provides detailed installation instructions for all security scanners supported by KALM. Each scanner has been tested and verified to work with the KALM benchmark platform.

## Quick Installation Summary

For users who want to install all scanners quickly:

### macOS (using Homebrew)

```bash
# Install via Homebrew
brew install kubescape kube-linter kube-bench trivy checkov kics polaris terrascan kube-score

# Install kubesec manually
curl -L "https://github.com/controlplaneio/kubesec/releases/latest/download/kubesec_darwin_arm64.tar.gz" -o /tmp/kubesec.tar.gz
cd /tmp && tar -xzf kubesec.tar.gz && chmod +x kubesec && mv kubesec ~/.local/bin/kubesec

# Install Snyk
npm install -g snyk

# Set environment variables
export SNYK_TOKEN=your_snyk_token_here
export PATH="$HOME/.local/bin:$PATH"
```

### Linux (Ubuntu/Debian)

```bash
# Install via package managers and direct downloads
# See individual scanner sections below for detailed instructions
```

## Individual Scanner Installation Instructions

### 1. Kubescape ✅

**Purpose**: Kubernetes security scanner with CCSS scoring
**Severity Support**: ✅ High, Medium, Low, Info

#### macOS

```bash
brew install kubescape
```

#### Linux

```bash
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```

#### Docker

```bash
docker run --rm -v ~/.kube:/root/.kube quay.io/kubescape/kubescape:latest
```

#### Verification

```bash
kubescape version
```

---

### 2. KubeLinter ✅

**Purpose**: Static analysis for Kubernetes YAML files
**Severity Support**: ✅ HIGH, MEDIUM, LOW (inferred by check type)

#### macOS

```bash
brew install kube-linter
```

#### Linux

```bash
# Download latest release
RELEASE=$(curl -s https://api.github.com/repos/stackrox/kube-linter/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
wget "https://github.com/stackrox/kube-linter/releases/download/${RELEASE}/kube-linter-linux.tar.gz"
tar -xzf kube-linter-linux.tar.gz
sudo mv kube-linter /usr/local/bin/
```

#### Verification

```bash
kube-linter version
```

---

### 3. KICS ✅

**Purpose**: Infrastructure as Code security scanner
**Severity Support**: ✅ HIGH, MEDIUM, LOW, INFO

#### macOS

```bash
brew install kics
```

#### Linux

```bash
# Download latest release
RELEASE=$(curl -s https://api.github.com/repos/Checkmarx/kics/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
wget "https://github.com/Checkmarx/kics/releases/download/${RELEASE}/kics_${RELEASE#v}_linux_x64.tar.gz"
tar -xzf kics_*.tar.gz
sudo mv kics /usr/local/bin/
```

#### Docker (Recommended)

```bash
docker run --rm -v $(pwd):/path checkmarx/kics:latest scan -p /path
```

#### Verification

```bash
kics version
```

---

### 4. Trivy ✅

**Purpose**: Vulnerability scanner for containers and Kubernetes
**Severity Support**: ✅ CRITICAL, HIGH, MEDIUM, LOW

#### macOS

```bash
brew install trivy
```

#### Linux

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

#### Verification

```bash
trivy --version
```

---

### 5. Checkov ✅

**Purpose**: Static analysis for Infrastructure as Code
**Severity Support**: ⚠️ Requires Bridgecrew/Prisma Cloud API key

#### macOS/Linux

```bash
pip install checkov
# or
brew install checkov
```

#### Docker

```bash
docker run --rm bridgecrew/checkov
```

#### Configuration

```bash
# For severity data, set API key:
export BC_API_KEY=your_bridgecrew_api_key
```

#### Verification

```bash
checkov --version
```

---

### 6. Polaris ✅

**Purpose**: Kubernetes best practices validator
**Severity Support**: ✅ danger, warning

#### macOS

```bash
brew install polaris
```

#### Linux

```bash
# Download latest release
RELEASE=$(curl -s https://api.github.com/repos/FairwindsOps/polaris/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
wget "https://github.com/FairwindsOps/polaris/releases/download/${RELEASE}/polaris_linux_amd64.tar.gz"
tar -xzf polaris_linux_amd64.tar.gz
sudo mv polaris /usr/local/bin/
```

#### Verification

```bash
polaris version
```

---

### 7. Terrascan ✅

**Purpose**: Static code analyzer for Infrastructure as Code
**Severity Support**: ✅ HIGH, MEDIUM, LOW

#### macOS

```bash
brew install terrascan
```

#### Linux

```bash
# Download latest binary
curl -L "$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest | grep -o -E "https://.+?_Linux_x86_64.tar.gz")" > terrascan.tar.gz
tar -xf terrascan.tar.gz terrascan && rm terrascan.tar.gz
sudo mv terrascan /usr/local/bin/ && chmod +x /usr/local/bin/terrascan
```

#### Verification

```bash
terrascan version
```

---

### 8. Kube-score ✅

**Purpose**: Kubernetes object analysis for security and reliability
**Severity Support**: ✅ Critical, Warning, Ok, Skipped (with numeric scoring)

#### macOS

```bash
brew install kube-score
```

#### Linux

```bash
# Download latest release
RELEASE=$(curl -s https://api.github.com/repos/zegl/kube-score/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
wget "https://github.com/zegl/kube-score/releases/download/${RELEASE}/kube-score_${RELEASE#v}_linux_amd64.tar.gz"
tar -xzf kube-score_*.tar.gz
sudo mv kube-score /usr/local/bin/
```

#### Verification

```bash
kube-score version
```

---

### 9. Snyk ✅

**Purpose**: Security scanner for dependencies and Infrastructure as Code
**Severity Support**: ✅ high, medium, low

#### macOS/Linux

```bash
# Via npm (recommended)
npm install -g snyk

# Via Homebrew (macOS)
brew install snyk/tap/snyk
```

#### Configuration (Required)

```bash
# Get token from https://app.snyk.io/account
export SNYK_TOKEN=your_snyk_token_here
snyk auth
```

#### Verification

```bash
snyk --version
```

---

### 10. Kubesec ✅

**Purpose**: Security risk analysis for Kubernetes resources
**Severity Support**: ✅ Numeric scoring (1, 3, etc.)

#### macOS

```bash
# Download latest release
ARCH=$(uname -m)
if [[ "$ARCH" == "arm64" ]]; then
    BINARY="kubesec_darwin_arm64.tar.gz"
else
    BINARY="kubesec_darwin_amd64.tar.gz"
fi

curl -L "https://github.com/controlplaneio/kubesec/releases/latest/download/$BINARY" -o /tmp/kubesec.tar.gz
cd /tmp && tar -xzf kubesec.tar.gz
chmod +x kubesec && mkdir -p ~/.local/bin && mv kubesec ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"
```

#### Linux

```bash
curl -L "https://github.com/controlplaneio/kubesec/releases/latest/download/kubesec_linux_amd64.tar.gz" -o /tmp/kubesec.tar.gz
cd /tmp && tar -xzf kubesec.tar.gz
chmod +x kubesec && sudo mv kubesec /usr/local/bin/
```

#### Docker

```bash
docker run -i kubesec/kubesec:latest scan /dev/stdin < your-file.yaml
```

#### Verification

```bash
kubesec version
```

---

### 11. Kube-bench ✅ (Cluster-based)

**Purpose**: CIS Kubernetes Benchmark security scanner
**Severity Support**: ✅ HIGH, MEDIUM, LOW (based on check status)

#### macOS

```bash
brew install kube-bench
```

#### Linux

```bash
# Download latest release
RELEASE=$(curl -s https://api.github.com/repos/aquasecurity/kube-bench/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
wget "https://github.com/aquasecurity/kube-bench/releases/download/${RELEASE}/kube-bench_${RELEASE#v}_linux_amd64.tar.gz"
tar -xzf kube-bench_*.tar.gz
sudo mv kube-bench /usr/local/bin/
```

#### Requirements

- Requires a running Kubernetes cluster
- Must be run with cluster access (`-c` flag in KALM)

#### Verification

```bash
kube-bench version
```

---

### 12. KubiScan ✅ (Cluster-based)

**Purpose**: Kubernetes cluster security scanner for RBAC risks
**Severity Support**: ✅ CRITICAL, HIGH, LOW

#### Installation

KubiScan is not formally packaged but available as a Python script. KALM expects it to be available as `kubiscan` command.

#### Setup for KALM

```bash
# Clone the repository
git clone https://github.com/cyberark/KubiScan.git
cd KubiScan

# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create alias or script
echo '#!/bin/bash
cd /path/to/KubiScan
source venv/bin/activate
python KubiScan.py "$@"' > ~/kubiscan.sh
chmod +x ~/kubiscan.sh

# Create symlink
sudo ln -s ~/kubiscan.sh /usr/local/bin/kubiscan
```

#### Requirements

- Requires a running Kubernetes cluster
- Must be run with cluster access (`-c` flag in KALM)

#### Verification

```bash
kubiscan -h
```

---

## Cluster Setup for Cluster-based Scanners

Some scanners (kube-bench, kubiscan) require a running Kubernetes cluster. KALM provides deployment scripts:

### Using Kind (Recommended for testing)

```bash
# Install kind
brew install kind  # macOS
# or download from https://kind.sigs.k8s.io/docs/user/quick-start/

# Create cluster with KALM manifests
kind create cluster --config=cluster.yaml
kubectl apply -f manifests/
```

### Using existing cluster

```bash
# Set kubectl context to your cluster
kubectl config use-context your-cluster-context

# Deploy KALM test manifests
kubectl apply -f manifests/
```

## Testing Your Installation

### Test manifest-based scanners

```bash
# Test individual scanner
poetry run cli scan Kubescape -f manifests/pod-032-2-privileged-container.yaml

# Test all manifest scanners
for scanner in Kubescape KubeLinter KICS trivy Checkov polaris Terrascan kube-score Snyk kubesec; do
    echo "Testing $scanner..."
    poetry run cli scan $scanner -f manifests/
done
```

### Test cluster-based scanners

```bash
# Ensure cluster is running and manifests are deployed
kubectl get pods --all-namespaces

# Test cluster scanners
poetry run cli scan kube-bench -c
poetry run cli scan kubiscan -c
```

### Verify severity extraction

```bash
# Check database for severity data
poetry run cli db-stats

# Or use direct SQLite query
sqlite3 data/kalm.db "
SELECT 
  scanner_name, 
  COUNT(*) as total_results,
  COUNT(CASE WHEN severity IS NOT NULL AND severity <> '' THEN 1 END) as with_severity,
  ROUND(100.0 * COUNT(CASE WHEN severity IS NOT NULL AND severity <> '' THEN 1 END) / COUNT(*), 1) as severity_percentage
FROM scanner_results 
GROUP BY scanner_name 
ORDER BY severity_percentage DESC;
"
```

## Troubleshooting

### Common Issues

#### Scanner not found

- Ensure the scanner binary is in your `PATH`
- Try running the scanner command directly to test installation
- Check if you need to restart your terminal after installation

#### Permission issues

- Use `chmod +x` to make binaries executable
- Consider installing to `~/.local/bin` instead of system directories
- For Docker-based scanners, ensure Docker daemon is running

#### Cluster access issues

- Verify `kubectl` can access your cluster: `kubectl get nodes`
- Ensure manifests are deployed: `kubectl get pods --all-namespaces`
- Check cluster context: `kubectl config current-context`

#### Missing severity data

- Some scanners require API keys (Snyk, Checkov with full features)
- Verify scanner output format hasn't changed
- Check KALM logs for parsing errors

### Getting Help

- KALM Issues: <https://github.com/dynatrace-oss/Kalm-Benchmark/issues>
- Scanner-specific issues: Check individual scanner repositories
- Community support: See README.md for contributing guidelines

## Scanner Compatibility Matrix

| Scanner | macOS | Linux | Windows | Docker | Cluster Required | API Key Required |
|---------|-------|-------|---------|--------|------------------|------------------|
| Kubescape | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| KubeLinter | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| KICS | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Trivy | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Checkov | ✅ | ✅ | ✅ | ✅ | ❌ | ⚠️* |
| Polaris | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Terrascan | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Kube-score | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Snyk* | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Kubesec | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Kube-bench | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ |
| KubiScan | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |

*Severity data requires API key; basic functionality works without it.

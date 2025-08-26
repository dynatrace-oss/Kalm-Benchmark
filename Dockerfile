ARG PYTHON_VERSION=3.10

FROM python:${PYTHON_VERSION}

ARG NODE_VERSION=18.2.0
ENV FNM_DIR=/root/.fnm \
    FNM_INTERACTIVE_CLI=false

# Install system dependencies and setup Node.js
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt update && apt upgrade -y && apt install -y curl docker.io git && \
    rm -rf /var/lib/apt/lists/*

# Install and setup fnm and Node.js
RUN curl -fsSL https://fnm.vercel.app/install | bash -s -- --install-dir "/opt/fnm" --skip-shell && \
    ln -s /opt/fnm/fnm /usr/bin/ && chmod +x /usr/bin/fnm && \
    eval "$(fnm env)" && \
    fnm install ${NODE_VERSION} && \
    fnm use ${NODE_VERSION} && \
    fnm alias default ${NODE_VERSION}

ENV PATH="${FNM_DIR}/aliases/default/bin/:${PATH}"

ENV WORKDIR=/usr/src/app
WORKDIR ${WORKDIR}

# Install poetry and Python/Node scanners
# configuration inspired by https://github.com/python-poetry/poetry/discussions/1879#discussioncomment-216865
ENV POETRY_HOME="/opt/poetry" \
    # do not ask any interactive question
    POETRY_NO_INTERACTION=1  \
    # make poetry create the virtual environment in the project's root it gets named `.venv`
    POETRY_VIRTUALENVS_IN_PROJECT=true

# prepend poetry and venv to path
ENV PATH="$POETRY_HOME/bin:$WORKDIR/.venv/bin:$PATH"

RUN curl -sSL https://install.python-poetry.org | python - && \
    npm install cdk8s-cli && \
    npm install -g snyk && \
    python3 -m venv /opt/checkov-venv && \
    /opt/checkov-venv/bin/pip install --upgrade pip setuptools && \
    /opt/checkov-venv/bin/pip install checkov && \
    ln -s /opt/checkov-venv/bin/checkov /usr/local/bin/checkov

# Install all binary scanners in a single RUN instruction
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    curl -L "$(curl -s https://api.github.com/repos/controlplaneio/kubesec/releases/latest | grep -o -E "https://.+?_linux_amd64.tar.gz")" > kubesec.tar.gz && \
    tar -xf kubesec.tar.gz kubesec && rm kubesec.tar.gz && \
    install kubesec /usr/local/bin && rm kubesec && \
    git clone https://github.com/cyberark/KubiScan.git /opt/KubiScan && \
    pip install -r /opt/KubiScan/requirements.txt && \
    chmod +x /opt/KubiScan/KubiScan.py && \
    ln -s /opt/KubiScan/KubiScan.py /usr/local/bin/kubiscan && \
    echo '#!/bin/bash\n# KICS wrapper script\nif ! docker info >/dev/null 2>&1; then\n    echo "Docker daemon not available. Start with --privileged or mount Docker socket."\n    exit 1\nfi\ndocker run --rm -t -v "$(pwd)":/path checkmarx/kics:latest "$@"' > /usr/local/bin/kics && \
    chmod +x /usr/local/bin/kics && \
    curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash && \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ARCH_NAME="x86_64"; ARCH_SUFFIX="amd64"; elif [ "$ARCH" = "aarch64" ]; \
    then ARCH_NAME="arm64"; ARCH_SUFFIX="arm64"; else ARCH_NAME="x86_64"; ARCH_SUFFIX="amd64"; fi && \
    curl -L "$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest | grep -o -E "https://.+?_Linux_${ARCH_NAME}.tar.gz")" > terrascan.tar.gz && \
    tar -xf terrascan.tar.gz terrascan && rm terrascan.tar.gz && \
    install terrascan /usr/local/bin && rm terrascan && \
    curl -L "$(curl -s https://api.github.com/repos/stackrox/kube-linter/releases/latest | grep -o -E "https://.+?-linux.tar.gz")" > kube-linter.tar.gz && \
    tar -xf kube-linter.tar.gz kube-linter && rm kube-linter.tar.gz && \
    install kube-linter /usr/local/bin && rm kube-linter && \
    curl -L "$(curl -s https://api.github.com/repos/zegl/kube-score/releases/latest | grep -o -E "https://.+?_linux_${ARCH_SUFFIX}.tar.gz")" > kube-score.tar.gz && \
    tar -xf kube-score.tar.gz kube-score && rm kube-score.tar.gz && \
    install kube-score /usr/local/bin && rm kube-score && \
    curl -L "$(curl -s https://api.github.com/repos/FairwindsOps/polaris/releases/latest | grep -o -E "https://.+?_linux_${ARCH_SUFFIX}.tar.gz")" > polaris.tar.gz && \
    tar -xf polaris.tar.gz polaris && rm polaris.tar.gz && \
    install polaris /usr/local/bin && rm polaris

COPY ./ ./

RUN poetry install --without dev
EXPOSE 8501

# ensure the latest manifests are in the container
RUN poetry run cli generate

ENTRYPOINT ["poetry", "run", "cli"]
# if no arguments are provided start the UI
CMD ["serve"]

ARG PYTHON_VERSION=3.10

FROM python:${PYTHON_VERSION}

ARG NODE_VERSION=18.2.0
ENV FNM_DIR=/root/.fnm \
    FNM_INTERACTIVE_CLI=false

RUN apt update && apt upgrade -y  && apt install -y curl

# install fnm to install and manage Node versions
RUN curl -fsSL https://fnm.vercel.app/install | bash -s -- --install-dir "/opt/fnm" --skip-shell && \
    ln -s /opt/fnm/fnm /usr/bin/ && chmod +x /usr/bin/fnm
RUN eval "$(fnm env)" && \
    fnm install ${NODE_VERSION} && \
    fnm use ${NODE_VERSION} && \
    fnm alias default ${NODE_VERSION}

ENV PATH="${FNM_DIR}/aliases/default/bin/:${PATH}"

ENV WORKDIR=/usr/src/app
WORKDIR ${WORKDIR}
# verify node works
RUN npm install cdk8s-cli
# RUN eval "$(fnm env)" && npm install cdk8s-cli


# install poetry so it's available for other images
# configuration inspired by https://github.com/python-poetry/poetry/discussions/1879#discussioncomment-216865
ENV POETRY_HOME="/opt/poetry" \
    # do not ask any interactive question
    POETRY_NO_INTERACTION=1  \
    # make poetry create the virtual environment in the project's root it gets named `.venv`
    POETRY_VIRTUALENVS_IN_PROJECT=true

# prepend poetry and venv to path
ENV PATH="$POETRY_HOME/bin:$WORKDIR/.venv/bin:$PATH"

# install poetry - respects $POETRY_HOME & $POETRY_VERSION
RUN curl -sSL https://install.python-poetry.org | python -
RUN pip install --upgrade pip


# install the supported scanners (if possible)
RUN pip install checkov && \
    # datree
    curl https://get.datree.io | /bin/bash  && \
    # terrascan
    curl -L "$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest | grep -o -E "https://.+?_Linux_x86_64.tar.gz")" > terrascan.tar.gz && \
    tar -xf terrascan.tar.gz terrascan && rm terrascan.tar.gz && \
    install terrascan /usr/local/bin && rm terrascan

COPY ./ ./

RUN poetry install --without dev
EXPOSE 8501

# ensure the latest manifests are in the container
RUN poetry run cli generate

ENTRYPOINT ["poetry", "run", "cli"]
# if no arguments are provided start the UI
CMD ["serve"]

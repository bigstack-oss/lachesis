# Force the base image to be amd64 regardless of your host (M4)
FROM --platform=linux/amd64 golang:1.25-bookworm

# Install build-essential and kernel headers
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    bpftool \
    linux-headers-amd64 \
    build-essential \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# golangci-lint, pinned to the version .github/workflows/ci.yml installs.
# It lives in the image so `task lint` is the SAME analysis CI runs: the
# linters' facts depend on a natively-typechecking tree, and cross-compiling
# from a darwin host loses them (staticcheck stops knowing that
# testing.T.Fatalf does not return, and reports SA5011 on correct code).
# Bump this and the workflow's version together.
ARG GOLANGCI_LINT_VERSION=2.12.2
RUN curl -sSfL       "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_LINT_VERSION}/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-amd64.tar.gz"     | tar -xz -C /tmp     && mv "/tmp/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-amd64/golangci-lint" /usr/local/bin/     && rm -rf /tmp/golangci-lint-*     && golangci-lint --version

RUN useradd -u 1000 -m bigstack
USER bigstack

WORKDIR /app
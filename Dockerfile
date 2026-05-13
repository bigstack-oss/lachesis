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
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 1000 -m bigstack
USER bigstack

WORKDIR /app
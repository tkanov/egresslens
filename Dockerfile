# EgressLens Docker Image
# Pre-built Ubuntu image with strace installed for network monitoring
FROM ubuntu:24.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install strace and basic utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    strace \
    curl \
    ca-certificates \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Create symlinks for python and pip (python3 -> python, pip3 -> pip)
RUN ln -sf /usr/bin/python3 /usr/bin/python && \
    ln -sf /usr/bin/pip3 /usr/bin/pip

# Set working directory
WORKDIR /work

# No default entrypoint - commands will be run explicitly by the CLI

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
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /work

# No default entrypoint - commands will be run explicitly by the CLI

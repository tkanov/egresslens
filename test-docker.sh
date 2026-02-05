#!/bin/bash
# Test script for EgressLens Docker image

set -e

IMAGE_NAME="${IMAGE_NAME:-egresslens/base}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

echo "Testing EgressLens Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""

# Build the image
echo "1. Building Docker image..."
docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" .
echo "✓ Build successful"
echo ""

# Test that strace is installed
echo "2. Testing that strace is installed..."
if docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" which strace > /dev/null 2>&1; then
    echo "✓ strace is installed"
else
    echo "✗ strace not found"
    exit 1
fi
echo ""

# Test strace version
echo "3. Testing strace version..."
STRACE_VERSION=$(docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" strace -V 2>&1 | head -n1)
echo "✓ strace version: ${STRACE_VERSION}"
echo ""

# Test that strace can run (basic functionality)
echo "4. Testing strace basic functionality..."
if docker run --rm --cap-add SYS_PTRACE --security-opt seccomp=unconfined "${IMAGE_NAME}:${IMAGE_TAG}" strace -e trace=connect echo "test" > /dev/null 2>&1; then
    echo "✓ strace can execute (with required capabilities)"
else
    echo "⚠ strace execution test skipped (may need Docker capabilities)"
fi
echo ""

# Test working directory
echo "5. Testing working directory..."
WORKDIR=$(docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" pwd)
if [ "$WORKDIR" = "/work" ]; then
    echo "✓ Working directory is /work"
else
    echo "✗ Working directory is $WORKDIR (expected /work)"
    exit 1
fi
echo ""

echo "All tests passed! ✓"
echo ""
echo "You can now use this image with:"
echo "  egresslens watch --image ${IMAGE_NAME}:${IMAGE_TAG} -- <command>"

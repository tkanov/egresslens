#!/bin/bash
# Build script for EgressLens Docker image

set -e

IMAGE_NAME="${IMAGE_NAME:-egresslens/base}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

echo "Building EgressLens Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"

docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" .

echo "Build complete!"
echo "To use this image, set --image=${IMAGE_NAME}:${IMAGE_TAG} when running egresslens watch"

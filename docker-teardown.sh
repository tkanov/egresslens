#!/bin/bash
# Teardown script for EgressLens Docker image

set -e

IMAGE_NAME="${IMAGE_NAME:-egresslens/base}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
FULL_IMAGE_NAME="${IMAGE_NAME}:${IMAGE_TAG}"

echo "Removing EgressLens Docker image: ${FULL_IMAGE_NAME}"

# First, remove all containers using this image
echo "Removing containers using ${FULL_IMAGE_NAME}..."
CONTAINERS=$(docker ps -a --filter ancestor="${FULL_IMAGE_NAME}" --format "{{.ID}}")
if [ -n "$CONTAINERS" ]; then
    echo "$CONTAINERS" | xargs -r docker rm -f
    echo "Containers removed."
else
    echo "No containers found using this image."
fi

# Check if image exists before attempting to remove
if docker image inspect "${FULL_IMAGE_NAME}" >/dev/null 2>&1; then
    docker rmi "${FULL_IMAGE_NAME}"
    echo "Image ${FULL_IMAGE_NAME} removed successfully!"
else
    echo "Image ${FULL_IMAGE_NAME} not found. Nothing to remove."
    exit 0
fi

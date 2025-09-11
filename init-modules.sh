#!/bin/bash

# Initialize Go modules for OTC Route Manager
# Run this script before building the Docker image

set -e

echo "Initializing Go modules..."

# Clean any existing modules
rm -f go.sum

# Initialize with Go 1.21 compatible versions
go mod init otc-route-manager 2>/dev/null || true

# Set Go version
go mod edit -go=1.21

# Add required dependencies with compatible versions
go mod edit -require=github.com/gophercloud/gophercloud@v1.7.0
go mod edit -require=github.com/prometheus/client_golang@v1.16.0
go mod edit -require=k8s.io/api@v0.28.3
go mod edit -require=k8s.io/apimachinery@v0.28.3
go mod edit -require=k8s.io/client-go@v0.28.3

# Download and tidy modules
go mod download
go mod tidy

echo "Go modules initialized successfully!"
echo "You can now run: make docker-build"

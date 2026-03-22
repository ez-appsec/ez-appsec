#!/bin/bash
# Build script for ez-appsec Docker images

set -e

echo "🐳 Building ez-appsec Docker images..."

# Build main image
echo "📦 Building standard image (ez-appsec:latest)..."
docker build -t ez-appsec:latest .
STANDARD_SIZE=$(docker images ez-appsec:latest --format "{{.Size}}")
echo "✓ Standard image size: $STANDARD_SIZE"

# Build slim image
echo "📦 Building slim image (ez-appsec:slim)..."
docker build -f Dockerfile.slim -t ez-appsec:slim .
SLIM_SIZE=$(docker images ez-appsec:slim --format "{{.Size}}")
echo "✓ Slim image size: $SLIM_SIZE"

# Test images
echo "🧪 Testing images..."
docker run --rm ez-appsec:latest --version
docker run --rm ez-appsec:slim --version

echo "✓ Testing scanner availability..."
docker run --rm ez-appsec:latest status
docker run --rm ez-appsec:slim status
echo "🧪 Testing individual scanners..."
docker run --rm ez-appsec:latest gitleaks version
docker run --rm ez-appsec:latest semgrep --version
docker run --rm ez-appsec:latest kics version
docker run --rm ez-appsec:latest grype version
echo ""
echo "✅ Docker build complete!"
echo ""
echo "Image Summary:"
echo "  Standard: $STANDARD_SIZE (ez-appsec:latest)"
echo "  Slim:     $SLIM_SIZE (ez-appsec:slim)"
echo ""
echo "Usage:"
echo "  docker run --rm -v \$(pwd):/scan ez-appsec:latest scan ."
echo "  docker run --rm -v \$(pwd):/scan ez-appsec:slim scan ."

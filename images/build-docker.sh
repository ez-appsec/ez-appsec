#!/bin/bash
# Build script for ez-appsec Docker images

set -e

echo "🐳 Building ez-appsec Docker images..."

# Build main image
echo "📦 Building standard image (ez-appsec:latest)..."
docker build -f images/Dockerfile -t ez-appsec:latest .
STANDARD_SIZE=$(docker images ez-appsec:latest --format "{{.Size}}")
echo "✓ Standard image size: $STANDARD_SIZE"

# Build slim image
echo "📦 Building slim image (ez-appsec:slim)..."
docker build -f images/Dockerfile.slim -t ez-appsec:slim .
SLIM_SIZE=$(docker images ez-appsec:slim --format "{{.Size}}")
echo "✓ Slim image size: $SLIM_SIZE"

# Build thin image
echo "📦 Building thin image (ez-appsec:thin)..."
docker build -f images/Dockerfile.thin -t ez-appsec:thin .
THIN_SIZE=$(docker images ez-appsec:thin --format "{{.Size}}")
echo "✓ Thin image size: $THIN_SIZE"

# Test images
echo "🧪 Testing images..."
docker run --rm ez-appsec:latest --version
docker run --rm ez-appsec:slim --version
docker run --rm ez-appsec:thin --version

echo "✓ Testing scanner availability..."
docker run --rm ez-appsec:latest status
docker run --rm ez-appsec:slim status
docker run --rm ez-appsec:thin status
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
echo "  Thin:     $THIN_SIZE (ez-appsec:thin)"
echo ""
echo "Usage:"
echo "  docker run --rm -v \$(pwd):/scan ez-appsec:latest scan ."
echo "  docker run --rm -v \$(pwd):/scan ez-appsec:slim scan ."
echo "  docker run --rm -v \$(pwd):/scan ez-appsec:thin scan ."

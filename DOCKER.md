docker-compose.yml

# Build instructions
Build the image (from project root):
```bash
docker build -t ez-appsec:latest .
docker build -t ez-appsec:slim --target builder .  # For lighter debugging
```

# Run security scan on local directory
```bash
docker run --rm -v $(pwd):/scan ez-appsec scan .
docker run --rm -v $(pwd):/scan ez-appsec status
```

# Run container interactively
```bash
docker run --rm -it -v $(pwd):/scan ez-appsec /bin/bash
```

# Check scanner versions
```bash
docker run --rm ez-appsec:latest gitleaks version
docker run --rm ez-appsec:latest semgrep --version
docker run --rm ez-appsec:latest kics version
docker run --rm ez-appsec:latest grype version
```

# Run individual scanners directly
```bash
# Gitleaks secrets scan
docker run --rm -v $(pwd):/scan ez-appsec:latest gitleaks detect --source /scan

# Semgrep SAST scan
docker run --rm -v $(pwd):/scan ez-appsec:latest semgrep --config=p/security-audit /scan

# KICS IaC scan
docker run --rm -v $(pwd):/scan ez-appsec:latest kics scan -p /scan

# Grype vulnerability scan
docker run --rm -v $(pwd):/scan ez-appsec:latest grype dir:/scan
```

# Push to Docker Hub
```bash
docker tag ez-appsec:latest <username>/ez-appsec:latest
docker push <username>/ez-appsec:latest
```

# Expected image sizes
- alpine:latest: ~7MB
- Python + dependencies: ~150MB
- All scanners: ~300-400MB total
- Final image: ~400-500MB (optimized)

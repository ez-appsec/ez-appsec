# GitHub Actions Self-Hosted Runners

Comprehensive guide for setting up and managing self-hosted GitHub Actions runners for ez-appsec security scanning.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Runner Installation](#runner-installation)
4. [Label Strategy](#label-strategy)
5. [Infrastructure Options](#infrastructure-options)
6. [Configuration](#configuration)
7. [ez-appsec Integration](#ez-appsec-integration)
8. [Troubleshooting](#troubleshooting)
9. [Cost Comparison](#cost-comparison)

---

## Overview

### Why Self-Hosted Runners?

**Cost Savings**: GitHub Actions charges $0.008/minute after 2000 free minutes. Self-hosted runners use your infrastructure at predictable cost.

**Control & Privacy**: Run code on your own servers with full access control and data isolation.

**Performance**: Persistent runners avoid cold-start overhead, better for long-running scans.

**Docker Cache**: Pull images once to on-prem registry reduces bandwidth and speeds up builds.

### When to Use Self-Hosted Runners?

✅ **Use self-hosted when:**
- Organization exceeds free tier (2000 min/month)
- Need predictable monthly costs
- Want to scan large codebases frequently
- Have regulatory/compliance requirements for data residency

❌ **Use GitHub-hosted when:**
- Occasional CI/CD usage (<500 min/month)
- Small teams or personal projects
- Need simplicity over control

### Cost Scenarios

| Monthly CI Minutes | GitHub Actions Cost | Self-Hosted (4× $20/mo VM) | Savings |
|-------------------|-------------------|------------------------------------|--------|
| 2,000 | $16 | $80 | -$144 |
| 10,000 | $80 | $80 | $0 (break-even) |
| 50,000 | $400 | $80 | -$320 |
| 100,000 | $800 | $200 (10× $20) | -$600 |

**Rule of Thumb**: If you're paying more than $100/month for GitHub Actions, self-hosting likely saves money.

---

## Quick Start

### Option 1: Single Physical Server

```bash
# 1. Download runner
wget https://github.com/actions/runner/releases/download/v2.311.0/actions-runner-linux-amd64

# 2. Configure and run
./actions-runner-linux-amd64 configure \
  --url https://github.com/YOUR_ORG/REPO \
  --token YOUR_PAT \
  --name self-hosted-runner-1 \
  --labels self-hosted,security \
  --replace

./actions-runner-linux-amd64 run &
```

### Option 2: Docker Compose (Simple)

```bash
# docker-compose.yml
version: '3.8'

services:
  actions-runner-1:
    image: jfelten/ez-appsec:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./work:/actions-runner/_work
    environment:
      GITHUB_URL: https://github.com/YOUR_ORG/YOUR_REPO
      GITHUB_TOKEN: YOUR_PAT
      GITHUB_REPOSITORY: YOUR_ORG/YOUR_REPO
      RUNNER_NAME: runner-1
      RUNNER_LABELS: self-hosted,security
      RUNNER_WORK_DIR: /actions-runner/_work
      RUNNER_EPHEMERAL_URL: https://github.com/YOUR_ORG/YOUR_REPO
      RUNNER_REPLACE_EXISTING_RUNNER: true
      DOCKER_IMAGE: jfelten/ez-appsec:latest
      DOCKER_IMAGE_PULL_ALWAYS: false
      DOCKER_CACHE_FROM: jfelten/ez-appsec:latest
    restart: unless-stopped

# Start it
docker-compose up -d
```

### Option 3: Terraform Kubernetes

```bash
# 1. Initialize Terraform
terraform init

# 2. Apply from GitHub registry
terraform apply \
  -var github_token=$GITHUB_TOKEN \
  -var github_organization=$GITHUB_ORG

# 3. Get runner URLs
terraform output runner_urls
```

---

## Runner Installation

### Prerequisites

**Required:**
- GitHub Personal Access Token (PAT) with `repo` and `workflow` scopes
- For org-level runners: Admin role in GitHub organization
- Linux x64 machine or Kubernetes cluster
- Docker installed

**Optional but Recommended:**
- SSL/TLS certificates for HTTPS runners
- Monitoring (Prometheus, Grafana, Datadog)
- Log aggregation
- Resource limits (CPU, memory) on runners

### Downloading the Runner

```bash
# Select version
RUNNER_VERSION="v2.311.0"

# Download
wget https://github.com/actions/runner/releases/download/${RUNNER_VERSION}/actions-runner-linux-amd64 \
  -O actions-runner-linux-amd64.tar.gz

# Verify
wget https://github.com/actions/runner/releases/download/${RUNNER_VERSION}/actions-runner-linux-amd64.tar.gz.sha256

# Extract
tar -xzf actions-runner-linux-amd64.tar.gz

# Configure
./actions-runner-linux-amd64 configure \
  --url https://github.com/YOUR_ORG/YOUR_REPO \
  --token YOUR_PAT \
  --name self-hosted-runner-1 \
  --labels self-hosted,security \
  --work /tmp/runner-work \
  --replace
```

### Systemd Service (Recommended)

```bash
# Create service file
cat > /etc/systemd/system/actions-runner.service << 'EOF'
[Unit]
Description=GitHub Actions Runner
After=network.target
[Service]
Type=simple
User=actions-runner
WorkingDirectory=/tmp/runner
ExecStart=/tmp/runner/run.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable --now actions-runner.service
```

---

## Label Strategy

Labels allow GitHub to route workflows to specific runners:

### Organization-Level Labels

```bash
# Strategic labels
self-hosted        # All self-hosted runners
security             # Security scans (ez-appsec, CodeQL)
docker              # Docker-based workloads
frontend             # Frontend build/test
backend              # Backend build/test
data                 # Data processing jobs

# Configure runner with multiple labels
./actions-runner-linux-amd64 configure \
  --labels self-hosted,security,docker \
  --name security-runner-1
```

### Repository-Level Labels

```yaml
# .github/workflows/github-scan.yml
name: Security Scan

jobs:
  scan:
    runs-on: [self-hosted, security]  # Target specific runners
    container:
      image: jfelten/ez-appsec:latest
```

### Dynamic Scaling

Use [Actions Runner Controller](https://github.com/actions/runner-controller) with auto-scaling:

```yaml
# Terraform with auto-scaling
# Runner Controller monitors workflow queue and scales up/down based on demand
# Prevents over-provisioning
# Automatic cleanup of idle runners
```

### Best Practices

1. **Separate security runners**: Use dedicated `security` label for security tools
2. **Limit concurrent jobs**: Each runner should handle 1-2 concurrent workflows
3. **Group related jobs**: Same runner handles similar workload types
4. **Cache images locally**: Reduce Docker Hub pulls and bandwidth
5. **Use labels strategically**: Route different workloads to appropriate runners

---

## Infrastructure Options

### Physical Servers

| Provider | Starting Price | CPU/RAM | Use Case | Pros | Cons |
|-----------|--------------|------------|---------|-------|
| **DigitalOcean** | $4/mo | 2-4CPU, 8GB RAM | 1-10 runners | Simple, predictable | Limited scalability |
| **Hetzner** | $5/mo | 4-16CPU, 32-64GB RAM | 20+ runners | Powerful, cheap | Setup complexity |
| **OVH** | $4/mo | 4-16CPU, 32-64GB RAM | 10+ runners | Good value | Variable pricing |
| **Linode** | $5/mo | 2-8CPU, 16GB RAM | 1-10 runners | Developer-friendly | Higher cost/GB |

**Recommended for 5-20 runners:** Hetzner Auction or DigitalOcean

### Kubernetes (AKS, GKE, EKS)

| Provider | Control Plane | Node Price | Use Case | Pros |
|-----------|--------------|-----------|-------|
| **AWS EKS** | $0.10/hour | $72-730/mo | 10+ runners | Managed, integrated | Expensive |
| **GKE** | $0.10/hour | $74-140/mo | 10+ runners | Google integration | Expensive |
| **AKS** | $0.10/hour | $72-95/mo | 10+ runners | Azure integration | Moderate |
| **Self-managed k8s** | Variable | Node dependent | 20+ runners | Most flexible | High admin overhead |

**For 5-10 runners:**
- **Best value**: Self-managed on budget providers (Akamai, DigitalOcean, Vultr)
- **Cost range**: $150-300/month total infrastructure

### Serverless Containers

| Service | Starting Price | Use Case | Pros |
|---------|--------------|-----------|-------|
| **ECS Fargate** | $0.0125/GB-hour | 10+ runners | Pay-per-use, auto-scale | Cold starts |
| **AWS Lambda** | $0.000016/invocation | Spike workloads | Not for CI | Expensive at scale |
| **Google Cloud Run** | $0.0000025/GB-second | Event-driven | Auto-scale | Cold starts |

**Not recommended for CI workloads** (frequent, regular workloads)

### Hybrid Approach

```bash
# Use GitHub-hosted for quick PR checks
jobs:
  quick-check:
    runs-on: ubuntu-latest  # Fast cold start

# Use self-hosted for main branch scans
jobs:
  security-scan:
    runs-on: [self-hosted, security]  # Persistent runners
```

**Best of both worlds:**
- Fast PR feedback with GitHub-hosted
- Full control with self-hosted for heavy workloads

---

## Configuration

### Environment Variables

```bash
# Required
GITHUB_URL=https://github.com/YOUR_ORG/YOUR_REPO
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxx
GITHUB_REPOSITORY=YOUR_ORG/YOUR_REPO

# Optional
RUNNER_NAME=runner-1
RUNNER_LABELS=self-hosted,security
RUNNER_WORK_DIR=/home/actions-runner/_work
RUNNER_EPHEMERAL_URL=https://github.com/YOUR_ORG/YOUR_REPO
RUNNER_REPLACE_EXISTING_RUNNER=true
DOCKER_IMAGE=jfelten/ez-appsec:latest
DOCKER_IMAGE_PULL_ALWAYS=false
DOCKER_CACHE_FROM=jfelten/ez-appsec:latest
```

### Token Management

**Best Practices:**
- Use **organization secrets** instead of PATs
- Rotate runner registration tokens every 90 days
- Store tokens in secret manager (HashiCorp Vault, AWS Secrets Manager)
- Use separate token for each runner group
- Monitor token usage in GitHub org settings

**Organization Setup:**
```bash
# 1. Add runner group to organization
gh api --method PUT \
  orgs/YOUR_ORG/actions/runner-groups/SECURITY-RUNNERS \
  -f '{"default":true,"visibility":"all","runners":["security-runner-1","security-runner-2"],"allowed_repositories":["*"]}'

# 2. Create runner registration token as org secret
gh secret set SECURITY_RUNNER_TOKEN --org YOUR_ORG
```

---

## ez-appsec Integration

### Updated Workflow for Self-Hosted Runners

```yaml
# .github/workflows/github-scan-selfhosted.yml
name: Security Scan (Self-Hosted)

on:
  push:
    branches:
      - main
  pull_request:
    types: [opened, synchronize, reopened]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

env:
  EZ_APPSEC_VERSION: "latest"

jobs:
  scan:
    # Use self-hosted security runners
    runs-on: [self-hosted, security]
    container:
      image: jfelten/ez-appsec:${{ env.EZ_APPSEC_VERSION }}

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Cache ez-appsec image locally
        run: |
          if [ "$RUNNER_OS" = "linux" ]; then
            echo "Pulling ez-appsec image..."
            docker pull jfelten/ez-appsec:${{ env.EZ_APPSEC_VERSION }}
            echo "Using local cache"

      - name: Run ez-appsec scan
        run: |
          mkdir -p scan-results
          ez-appsec github-scan . --output scan-results/ez-appsec.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan-results/ez-appsec.sarif
          continue-on-error: true

      - name: Upload scan results as artifacts
        uses: actions/upload-artifact@v4
        with:
          name: ez-appsec-scan
          path: scan-results/
          retention-days: 7
          if-no-files-found: warn
```

### Key Differences from GitHub-Hosted

| Feature | GitHub-Hosted | Self-Hosted | Notes |
|---------|---------------|-------------|-------|
| **Startup time** | Instant | 30-60s | Self-hosted needs warm-up |
| **Cost predictability** | Variable | Predictable | Infrastructure planning |
| **Control** | Limited | Full | Resource limits, customization |
| **Docker layer** | Not applicable | Available | Cache locally, speed up |
| **Custom images** | Not applicable | Available | Use forked/custom images |

---

## Troubleshooting

### Runner Not Starting

**Symptoms:**
- Runner shows "offline" in GitHub
- Jobs stuck in "queued" state
- No logs from runner

**Solutions:**
```bash
# Check runner service
systemctl status actions-runner

# Check logs
journalctl -u actions-runner -f

# Restart runner
systemctl restart actions-runner

# Re-register if needed
./actions-runner-linux-amd64 configure --url https://github.com/YOUR_ORG/YOUR_REPO --token $TOKEN --replace
```

### Connection Issues

**Symptoms:**
- "dial tcp: lookup" errors
- TLS certificate errors

**Solutions:**
```bash
# Check firewall
sudo ufw allow from any to any port 443 comment 'GitHub Actions'
# Check DNS
nslookup github.com
# Verify token hasn't expired
gh auth status
```

### Resource Exhaustion

**Symptoms:**
- Runner becomes unresponsive
- Jobs timeout
- High CPU/memory usage

**Solutions:**
```bash
# Limit concurrent jobs per runner
./actions-runner-linux-amd64 configure \
  --max-jobs 2

# Add resource limits
systemctl set-property actions-runner.service MemoryMax=4G

# Monitor resources
htop
```

### Docker Image Pull Issues

**Symptoms:**
- Slow image pulls
- Registry rate limiting

**Solutions:**
```bash
# Use mirror registry
DOCKER_REGISTRY=mirror.gcr.io  # Your internal mirror
docker pull mirror.gcr.io/jfelten/ez-appsec:latest

# Cache images locally
docker save jfelten/ez-appsec:latest | gzip > ez-appsec.tar.gz
docker load < ez-appsec.tar.gz
```

---

## Cost Comparison

### Detailed Breakdown

**Example: 50 projects, 10K CI runs/month**

| Component | GitHub Actions (Paid) | Self-Hosted (4× $20/mo) |
|-----------|-------------------|------------------------------------|
| Runner minutes | 10,000 × $0.008 = $80 | Infrastructure = 4 × $20 = $80 |
| Storage | $0 | Included in server cost | $0 |
| Bandwidth | $0 | Included in server cost | $0 |
| **Total Monthly** | **$80** | **$80** |
| **Break-even point** | 2,000 min (16/mo) |

**Self-hosted wins when you exceed 2,000 CI minutes/month.**

### Scaling Economics

| Runners | Infrastructure Cost | Throughput (runs/hour) | Cost/1000 runs |
|----------|------------------|------------------|---------------|
| 2 | $40 | 500 | $0.08 |
| 4 | $80 | 1,000 | $0.08 |
| 6 | $120 | 1,500 | $0.08 |
| 8 | $160 | 2,000 | $0.08 |
| 10 | $200 | 2,500 | $0.08 |

**Key insight:** Diminishing returns after 6-8 runners. More runners don't linearly increase throughput.

---

## Next Steps

1. **Choose infrastructure**: Physical server, K8s, or ECS
2. **Start small**: 2-4 runners, scale based on usage
3. **Monitor**: Track GitHub Actions usage vs infrastructure costs
4. **Optimize**: Use labels, caching, and resource limits

---

## Additional Resources

- [GitHub Actions Runner Documentation](https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners)
- [Actions Runner Controller](https://github.com/actions/runner-controller)
- [Terraform GitHub Provider](https://registry.terraform.io/providers/github/index.html)
- [Docker Hub](https://hub.docker.com/r/jfelten/ez-appsec)
- [Cost Calculator](https://actions-cost-calculator.com/)

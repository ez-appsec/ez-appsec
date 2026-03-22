# Multi-stage build for minimal image size
FROM python:3.11-alpine as builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev git

# Create virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy and install ez-appsec
COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir -e .


FROM alpine:latest

# Install runtime dependencies only
RUN apk add --no-cache \
    python3 \
    git \
    curl \
    bash \
    ca-certificates \
    libffi \
    openssl

# Install external scanners from releases (pre-compiled to save space)
RUN apk add --no-cache \
    go \
    nodejs \
    npm

# Install gitleaks (lightweight secrets scanner)
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks-linux-arm64 -O /usr/local/bin/gitleaks 2>/dev/null || \
    wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks-linux-x64 -O /usr/local/bin/gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm -rf /tmp/* /var/cache/apk/*

# Install grype (vulnerability scanner)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && \
    rm -rf /tmp/* /var/cache/apk/*

# Install semgrep via pip (lighter than npm)
RUN apk add --no-cache build-base && \
    pip install --no-cache-dir semgrep && \
    apk del build-base && \
    rm -rf /tmp/* /var/cache/apk/*

# Install kics
RUN wget https://github.com/Checkmarx/kics/releases/download/v1.6.12/kics-alpine -O /usr/local/bin/kics && \
    chmod +x /usr/local/bin/kics && \
    rm -rf /tmp/* /var/cache/apk/*

# Copy Python virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set environment
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Create app directory
WORKDIR /scan

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ez-appsec --version || exit 1

# Default command
ENTRYPOINT ["ez-appsec"]
CMD ["--help"]

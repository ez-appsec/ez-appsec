# Pull kics binary from official image
FROM checkmarx/kics@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602 as kics

# Multi-stage build for minimal image size (pinned versions to satisfy hadolint)
FROM python:3.11.9-alpine3.18 as builder

SHELL ["/bin/ash", "-o", "pipefail", "-c"]

RUN apk add --no-cache \
    gcc=12.2.1_git20220924-r10 \
    musl-dev=1.2.4-r3 \
    libffi-dev=3.4.4-r2 \
    openssl-dev=3.1.8-r0 \
    git=2.40.4-r0

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy and build wheel
COPY . /app
RUN pip install --no-cache-dir build==1.4.0 && python -m build --wheel --outdir /dist


FROM alpine:3.18

SHELL ["/bin/ash", "-o", "pipefail", "-c"]

# Install runtime dependencies (pinned versions)
RUN apk add --no-cache \
    python3=3.11.12-r1 \
    git=2.40.4-r0 \
    curl=8.12.1-r0 \
    bash=5.2.15-r5 \
    ca-certificates=20241121-r1 \
    libffi=3.4.4-r2 \
    openssl=3.1.8-r0 \
    nodejs \
    npm && \
    python3 -m ensurepip && \
    python3 -m pip install --no-cache-dir --upgrade pip==26.0.1

# Install scanners with explicit versions or static binaries
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
      aarch64) GL_ARCH="arm64" ;; \
      x86_64)  GL_ARCH="x64" ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_${GL_ARCH}.tar.gz" \
      -o /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz && \
    chmod +x /usr/local/bin/gitleaks && \
    gitleaks version

RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && \
    grype version

# semgrep via pip with pinned version
RUN pip install --no-cache-dir semgrep==1.34.0 && \
    semgrep --version

# Bundle GitLab SAST rules (language dirs only — offline use, richer severity metadata)
RUN curl -sSfL "https://gitlab.com/gitlab-org/security-products/sast-rules/-/archive/main/sast-rules-main.tar.gz" \
      -o /tmp/sast-rules.tar.gz && \
    mkdir -p /tmp/sast-rules-extract /usr/local/share/sast-rules && \
    tar -xzf /tmp/sast-rules.tar.gz -C /tmp/sast-rules-extract && \
    for lang in c csharp go java javascript python scala; do \
      mv "/tmp/sast-rules-extract/sast-rules-main/$lang" /usr/local/share/sast-rules/; \
    done && \
    rm -rf /tmp/sast-rules.tar.gz /tmp/sast-rules-extract && \
    curl -sSfL "https://semgrep.dev/c/p/ruby" -o /usr/local/share/sast-rules/ruby.yml

# Copy kics binary and assets from official image
COPY --from=kics /app/bin/kics /usr/local/bin/kics
COPY --from=kics /app/bin/assets /usr/local/bin/assets
RUN kics version

# Install ez-appsec wheel and dependencies from builder
COPY --from=builder /dist/*.whl /tmp/
COPY --from=builder /app/requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt /tmp/*.whl && \
    rm /tmp/*.whl /tmp/requirements.txt

ENV PATH="/usr/local/bin:/usr/bin:/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Copy website files
COPY web/ /web/

WORKDIR /scan

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ez-appsec --version || exit 1

# Default command
ENTRYPOINT ["ez-appsec"]
CMD ["--help"]

Run the ez-appsec security scan using the local Dockerfile and output results.

## Steps

1. Determine the scan target. If the user provided a path argument (`$ARGUMENTS`), use it. Otherwise default to the current working directory (`.`).

2. Check if the `ez-appsec:local` Docker image exists:
   ```bash
   docker image inspect ez-appsec:local >/dev/null 2>&1
   ```
   If it does not exist (non-zero exit), build it from the project root and show progress:
   ```bash
   docker build -t ez-appsec:local "$(git rev-parse --show-toplevel)"
   ```

3. Run the scan by mounting the target path into the container:
   ```bash
   docker run --rm \
     -v "$(realpath <TARGET_PATH>):/scan" \
     ez-appsec:local \
     scan /scan
   ```
   The container's WORKDIR is `/scan` and the entrypoint is `ez-appsec`.

4. Display the full output to the user. Summarize:
   - Total issues found
   - Breakdown by severity (critical / high / medium / low)
   - Top 5 findings with file, line, and description
   - Which scanners ran (gitleaks, semgrep, grype, kics)

5. If the scan exits non-zero (scan errors, not findings), report the error clearly and suggest running `docker run --rm ez-appsec:local status` to verify all scanners are installed inside the image.

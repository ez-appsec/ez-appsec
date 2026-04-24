Reinstall the ez-appsec skills from the latest release (or a pinned tag), then report the version change.

## Usage

```
/ez-appsec update [tag]
```

`tag` is optional (e.g. `v1.8.0`). Omit to install from `main`.

---

## Execute

```bash
# ── Detect where skills are installed ────────────────────────────────────────
GLOBAL_FILE="${HOME}/.claude/commands/ez-appsec.md"
PROJECT_FILE=".claude/commands/ez-appsec.md"

if [ -f "$GLOBAL_FILE" ]; then
  INSTALLED_FILE="$GLOBAL_FILE"
  MODE="--global"
elif [ -f "$PROJECT_FILE" ]; then
  INSTALLED_FILE="$PROJECT_FILE"
  MODE="--project"
else
  echo "ez-appsec skills are not installed."
  echo "Install first:"
  echo "  curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh | bash"
  exit 1
fi

# ── Read current version ──────────────────────────────────────────────────────
CURRENT=$(sed -n 's/<!-- ez-appsec-skills: \(.*\) -->/\1/p' "$INSTALLED_FILE" 2>/dev/null || echo "unknown")

# ── Build install args ────────────────────────────────────────────────────────
TAG="${ARGUMENTS:-}"
TAG_ARG=""
[ -n "$TAG" ] && TAG_ARG="--tag ${TAG}"

# ── Run installer ─────────────────────────────────────────────────────────────
curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh \
  | bash -s -- ${MODE} ${TAG_ARG}

# ── Read new version ──────────────────────────────────────────────────────────
NEW=$(sed -n 's/<!-- ez-appsec-skills: \(.*\) -->/\1/p' "$INSTALLED_FILE" 2>/dev/null || echo "unknown")

# ── Report ────────────────────────────────────────────────────────────────────
echo ""
if [ "$CURRENT" = "$NEW" ]; then
  echo "ez-appsec skills already up to date  (${NEW})"
else
  echo "ez-appsec skills updated  ${CURRENT} → ${NEW}"
fi
```

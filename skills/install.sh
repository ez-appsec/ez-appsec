#!/usr/bin/env bash
# ez-appsec skill installer
#
# Usage (local):
#   ./skills/install.sh [OPTIONS]
#
# Usage (curl — always installs latest from main):
#   curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh | bash
#
# Usage (curl — pin to a specific release tag):
#   curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh | bash -s -- --tag v1.8.0
#
# Options:
#   --tag <tag>    Install skills from this git tag (default: main)
#   --global       Install Claude Code skills globally in ~/.claude/commands/  (default)
#   --project      Install Claude Code skills in .claude/commands/ of the current dir
#   --copilot      Append ez-appsec instructions to .github/copilot-instructions.md
#   --cursor       Add .cursor/rules/ez-appsec.md
#   --all          --global + --copilot + --cursor
#   --uninstall    Remove all files installed by this script
#   -h, --help     Show this help

set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────

GITHUB_REPO="ez-appsec/ez-appsec"
GLOBAL_CLAUDE_DIR="${HOME}/.claude/commands"
PROJECT_CLAUDE_DIR=".claude/commands"

# Canonical list: dispatcher + one entry per subcommand skill
DISPATCHER="ez-appsec"
SKILLS=(
  ez-appsec-install-app
  ez-appsec-install
  ez-appsec-install-dashboard
  ez-appsec-update-dashboard
  ez-appsec-uninstall-app
  ez-appsec-uninstall
  ez-appsec-scan
  ez-appsec-load-vulns
  ez-appsec-remediate
  ez-appsec-test
  ez-appsec-update
)

# ── Helpers ───────────────────────────────────────────────────────────────────

green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
red()    { printf '\033[31m%s\033[0m\n' "$*"; }

usage() {
  cat <<'EOF'
Usage: install.sh [OPTIONS]

  (none)           Install Claude Code skills globally (default)
  --tag <tag>      Install from a specific release tag (e.g. --tag v1.8.0)
  --global         Install globally in ~/.claude/commands/
  --project        Install in .claude/commands/ of the current directory
  --copilot        Append instructions to .github/copilot-instructions.md
  --cursor         Add .cursor/rules/ez-appsec.md
  --all            --global + --copilot + --cursor
  --uninstall      Remove all installed files
  -h, --help       Show this help

Examples:
  # Install latest
  curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh | bash

  # Install pinned to v1.8.0
  curl -fsSL https://raw.githubusercontent.com/ez-appsec/ez-appsec/main/skills/install.sh | bash -s -- --tag v1.8.0

  # Local install from clone
  ./skills/install.sh --global
EOF
}

# Detect whether we're running from a local clone or piped from curl.
# Returns the local skills/claude directory if usable, empty string otherwise.
local_skill_dir() {
  local src
  src="$(cd "$(dirname "${BASH_SOURCE[0]:-/dev/null}")" 2>/dev/null && pwd || echo "")"
  if [[ -n "$src" && -d "${src}/claude" ]]; then
    echo "${src}/claude"
  else
    echo ""
  fi
}

# Stamp the installed version into the dispatcher file.
# Replaces the %%VERSION%% placeholder with the actual version string.
stamp_version() {
  local file="$1" version="$2"
  if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s/%%VERSION%%/${version}/g" "$file"
  else
    sed -i "s/%%VERSION%%/${version}/g" "$file"
  fi
}

# ── Source resolution ─────────────────────────────────────────────────────────
# Fetch a skill file from remote (tag or main) and write to stdout.
fetch_remote() {
  local ref="$1" path="$2"
  curl -fsSL "https://raw.githubusercontent.com/${GITHUB_REPO}/${ref}/${path}"
}

# ── Install functions ─────────────────────────────────────────────────────────

install_skills() {
  local target_dir="$1"
  local version="$2"    # e.g. "v1.8.0" or "main"
  local ref="$3"        # git ref to fetch from (tag or "main")
  local local_dir="$4"  # path to local skills/claude/, or ""

  mkdir -p "${target_dir}"

  # Dispatcher: lives at .claude/commands/ez-appsec.md in the repo
  if [[ -n "$local_dir" ]]; then
    # Running from a local clone — dispatcher is one level up from skills/claude/
    local dispatcher_src
    dispatcher_src="$(dirname "${local_dir}")/../.claude/commands/${DISPATCHER}.md"
    cp "${dispatcher_src}" "${target_dir}/${DISPATCHER}.md"
  else
    fetch_remote "$ref" ".claude/commands/${DISPATCHER}.md" \
      > "${target_dir}/${DISPATCHER}.md"
  fi
  stamp_version "${target_dir}/${DISPATCHER}.md" "${version}"

  # Subcommand skills
  for skill in "${SKILLS[@]}"; do
    if [[ -n "$local_dir" && -f "${local_dir}/${skill}.md" ]]; then
      cp "${local_dir}/${skill}.md" "${target_dir}/${skill}.md"
    else
      fetch_remote "$ref" "skills/claude/${skill}.md" \
        > "${target_dir}/${skill}.md"
    fi
  done
}

do_install_global() {
  local version="$1" ref="$2" local_dir="$3"
  install_skills "${GLOBAL_CLAUDE_DIR}" "$version" "$ref" "$local_dir"
  green "✓ ez-appsec skills installed globally  (${version})"
  echo "  Location : ${GLOBAL_CLAUDE_DIR}/${DISPATCHER}.md"
  echo "  Usage    : /ez-appsec <subcommand>  (in any Claude Code session)"
}

do_install_project() {
  local version="$1" ref="$2" local_dir="$3"
  install_skills "${PROJECT_CLAUDE_DIR}" "$version" "$ref" "$local_dir"
  green "✓ ez-appsec skills installed for this project  (${version})"
  echo "  Location : ${PROJECT_CLAUDE_DIR}/${DISPATCHER}.md"
}

do_install_copilot() {
  mkdir -p ".github"
  local target=".github/copilot-instructions.md"
  if [[ -f "${target}" ]] && grep -q "ez-appsec" "${target}" 2>/dev/null; then
    yellow "ℹ  ez-appsec already in ${target} — skipping"
    return
  fi
  if [[ -n "$LOCAL_SKILL_DIR" && -f "${LOCAL_SKILL_DIR}/../copilot/instructions.md" ]]; then
    [[ -f "${target}" ]] && printf '\n' >> "${target}"
    cat "${LOCAL_SKILL_DIR}/../copilot/instructions.md" >> "${target}"
  else
    [[ -f "${target}" ]] && printf '\n' >> "${target}"
    fetch_remote "$REF" "skills/copilot/instructions.md" >> "${target}"
  fi
  green "✓ Copilot instructions updated  (${target})"
}

do_install_cursor() {
  mkdir -p ".cursor/rules"
  if [[ -n "$LOCAL_SKILL_DIR" && -f "${LOCAL_SKILL_DIR}/../cursor/ez-appsec.md" ]]; then
    cp "${LOCAL_SKILL_DIR}/../cursor/ez-appsec.md" ".cursor/rules/ez-appsec.md"
  else
    fetch_remote "$REF" "skills/cursor/ez-appsec.md" > ".cursor/rules/ez-appsec.md"
  fi
  green "✓ Cursor rule installed  (.cursor/rules/ez-appsec.md)"
}

# ── Uninstall ─────────────────────────────────────────────────────────────────

do_uninstall() {
  local removed=0
  local all_skills=("${DISPATCHER}" "${SKILLS[@]}")

  for dir in "${GLOBAL_CLAUDE_DIR}" "${PROJECT_CLAUDE_DIR}"; do
    for skill in "${all_skills[@]}"; do
      local f="${dir}/${skill}.md"
      if [[ -f "${f}" ]]; then
        rm "${f}"
        green "✓ Removed ${f}"
        removed=$((removed + 1))
      fi
    done
  done

  if [[ -f ".cursor/rules/ez-appsec.md" ]]; then
    rm ".cursor/rules/ez-appsec.md"
    green "✓ Removed .cursor/rules/ez-appsec.md"
    removed=$((removed + 1))
  fi

  if [[ $removed -eq 0 ]]; then
    yellow "Nothing to uninstall."
  fi

  if [[ -f ".github/copilot-instructions.md" ]] \
      && grep -q "ez-appsec" ".github/copilot-instructions.md" 2>/dev/null; then
    yellow "ℹ  .github/copilot-instructions.md has ez-appsec content — remove manually if desired"
  fi
}

# ── Argument parsing ──────────────────────────────────────────────────────────

TAG=""           # --tag value, empty = use main
MODE_GLOBAL=false
MODE_PROJECT=false
MODE_COPILOT=false
MODE_CURSOR=false
MODE_UNINSTALL=false

[[ $# -eq 0 ]] && MODE_GLOBAL=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)       TAG="$2"; shift 2 ;;
    --global)    MODE_GLOBAL=true; shift ;;
    --project)   MODE_PROJECT=true; shift ;;
    --copilot)   MODE_COPILOT=true; shift ;;
    --cursor)    MODE_CURSOR=true; shift ;;
    --all)       MODE_GLOBAL=true; MODE_COPILOT=true; MODE_CURSOR=true; shift ;;
    --uninstall) MODE_UNINSTALL=true; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) red "Unknown option: $1"; usage; exit 1 ;;
  esac
done

# ── Resolve version / ref / local source ─────────────────────────────────────

LOCAL_SKILL_DIR="$(local_skill_dir)"

if [[ -n "$TAG" ]]; then
  # Pinned install: fetch from that tag
  REF="$TAG"
  VERSION="$TAG"
elif [[ -n "$LOCAL_SKILL_DIR" ]]; then
  # Local clone: read VERSION file, install from local files
  VERSION_FILE="$(dirname "${LOCAL_SKILL_DIR}")/../VERSION"
  if [[ -f "$VERSION_FILE" ]]; then
    VERSION="v$(cat "$VERSION_FILE" | tr -d '[:space:]')"
  else
    VERSION="dev"
  fi
  REF="main"  # ref only used as fallback for files missing locally
else
  # Piped from curl with no --tag: install from main, label as "main"
  REF="main"
  VERSION="main"
fi

# ── Execute ───────────────────────────────────────────────────────────────────

if $MODE_UNINSTALL; then
  do_uninstall
  exit 0
fi

$MODE_GLOBAL  && do_install_global  "$VERSION" "$REF" "$LOCAL_SKILL_DIR" || true
$MODE_PROJECT && do_install_project "$VERSION" "$REF" "$LOCAL_SKILL_DIR" || true
$MODE_COPILOT && do_install_copilot || true
$MODE_CURSOR  && do_install_cursor  || true

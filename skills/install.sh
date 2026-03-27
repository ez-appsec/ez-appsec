#!/usr/bin/env bash
# ez-appsec skill installer
# Installs the /ez-appsec-scan command for Claude Code and optionally
# adds instructions for GitHub Copilot and Cursor.
#
# Usage:
#   ./skills/install.sh              # global Claude Code install (default)
#   ./skills/install.sh --project    # project-level Claude Code install
#   ./skills/install.sh --copilot    # append to .github/copilot-instructions.md
#   ./skills/install.sh --cursor     # add .cursor/rules/ez-appsec.md
#   ./skills/install.sh --all        # all of the above (global)
#   ./skills/install.sh --uninstall  # remove all installed files

set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GLOBAL_CLAUDE_DIR="${HOME}/.claude/commands"
PROJECT_CLAUDE_DIR=".claude/commands"
SKILL_NAME="ez-appsec-scan"
INSTALL_SKILL_NAME="ez-appsec-install"
PIPELINE_SCAN_SKILL_NAME="ez-appsec-pipeline-scan"
UPDATE_VULNS_SKILL_NAME="ez-appsec-update-vulns"
LOCAL_SCAN_SKILL_NAME="ez-appsec-local-scan"

# ── helpers ──────────────────────────────────────────────────────────────────

green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
red()    { printf '\033[31m%s\033[0m\n' "$*"; }

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  (none)         Install Claude Code skills globally  (default)
  --project      Install Claude Code skills in the current project only
  --copilot      Append ez-appsec instructions to .github/copilot-instructions.md
  --cursor       Add Cursor rule to .cursor/rules/ez-appsec.md
  --all          Install globally for Claude Code + Copilot + Cursor
  --uninstall    Remove all files installed by this script
  -h, --help     Show this help

Installs two Claude Code slash commands:
  /ez-appsec-scan     Run a security scan on a directory
  /ez-appsec-install  Install ez-appsec into a GitLab project via scan.yml include + MR

Examples:
  ./skills/install.sh
  ./skills/install.sh --all
  ./skills/install.sh --project --copilot
  curl -fsSL https://raw.githubusercontent.com/jfelten/ez-appsec/main/skills/install.sh | bash
EOF
}

# ── install functions ─────────────────────────────────────────────────────────

install_claude_global() {
  mkdir -p "${GLOBAL_CLAUDE_DIR}"
  cp "${SKILL_DIR}/claude/${SKILL_NAME}.md" "${GLOBAL_CLAUDE_DIR}/${SKILL_NAME}.md"
  cp "${SKILL_DIR}/claude/${INSTALL_SKILL_NAME}.md" "${GLOBAL_CLAUDE_DIR}/${INSTALL_SKILL_NAME}.md"
  cp "${SKILL_DIR}/claude/${PIPELINE_SCAN_SKILL_NAME}.md" "${GLOBAL_CLAUDE_DIR}/${PIPELINE_SCAN_SKILL_NAME}.md"
  cp "${SKILL_DIR}/claude/${UPDATE_VULNS_SKILL_NAME}.md" "${GLOBAL_CLAUDE_DIR}/${UPDATE_VULNS_SKILL_NAME}.md"
  cp "${SKILL_DIR}/claude/${LOCAL_SCAN_SKILL_NAME}.md" "${GLOBAL_CLAUDE_DIR}/${LOCAL_SCAN_SKILL_NAME}.md"
  green "✓ Claude Code skills installed globally"
  echo "  Location : ${GLOBAL_CLAUDE_DIR}/${SKILL_NAME}.md"
  echo "  Location : ${GLOBAL_CLAUDE_DIR}/${INSTALL_SKILL_NAME}.md"
  echo "  Location : ${GLOBAL_CLAUDE_DIR}/${PIPELINE_SCAN_SKILL_NAME}.md"
  echo "  Location : ${GLOBAL_CLAUDE_DIR}/${UPDATE_VULNS_SKILL_NAME}.md"
  echo "  Location : ${GLOBAL_CLAUDE_DIR}/${LOCAL_SCAN_SKILL_NAME}.md"
  echo "  Usage    : /ez-appsec-local-scan [path]    — run a local scan via Docker"
  echo "  Usage    : /ez-appsec-scan [path]          — run a local security scan"
  echo "  Usage    : /ez-appsec-install [path]       — install into a GitLab project"
  echo "  Usage    : /ez-appsec-pipeline-scan [path] — trigger and report scan:pipeline"
  echo "  Usage    : /ez-appsec-update-vulns [path]  — trigger update:vulns to publish report"
}

install_claude_project() {
  mkdir -p "${PROJECT_CLAUDE_DIR}"
  cp "${SKILL_DIR}/claude/${SKILL_NAME}.md" "${PROJECT_CLAUDE_DIR}/${SKILL_NAME}.md"
  cp "${SKILL_DIR}/claude/${INSTALL_SKILL_NAME}.md" "${PROJECT_CLAUDE_DIR}/${INSTALL_SKILL_NAME}.md"
  cp "${SKILL_DIR}/claude/${PIPELINE_SCAN_SKILL_NAME}.md" "${PROJECT_CLAUDE_DIR}/${PIPELINE_SCAN_SKILL_NAME}.md"
  cp "${SKILL_DIR}/claude/${UPDATE_VULNS_SKILL_NAME}.md" "${PROJECT_CLAUDE_DIR}/${UPDATE_VULNS_SKILL_NAME}.md"
  cp "${SKILL_DIR}/claude/${LOCAL_SCAN_SKILL_NAME}.md" "${PROJECT_CLAUDE_DIR}/${LOCAL_SCAN_SKILL_NAME}.md"
  green "✓ Claude Code skills installed for this project"
  echo "  Location : ${PROJECT_CLAUDE_DIR}/${SKILL_NAME}.md"
  echo "  Location : ${PROJECT_CLAUDE_DIR}/${INSTALL_SKILL_NAME}.md"
  echo "  Location : ${PROJECT_CLAUDE_DIR}/${PIPELINE_SCAN_SKILL_NAME}.md"
  echo "  Location : ${PROJECT_CLAUDE_DIR}/${UPDATE_VULNS_SKILL_NAME}.md"
  echo "  Location : ${PROJECT_CLAUDE_DIR}/${LOCAL_SCAN_SKILL_NAME}.md"
  echo "  Usage    : /ez-appsec-local-scan [path]"
  echo "  Usage    : /ez-appsec-scan [path]"
  echo "  Usage    : /ez-appsec-install [path]"
  echo "  Usage    : /ez-appsec-pipeline-scan [path]"
  echo "  Usage    : /ez-appsec-update-vulns [path]"
}

install_copilot() {
  mkdir -p ".github"
  local target=".github/copilot-instructions.md"
  if [[ -f "${target}" ]]; then
    if grep -q "ez-appsec" "${target}" 2>/dev/null; then
      yellow "ℹ  ez-appsec already present in ${target} — skipping"
      return
    fi
    printf '\n' >> "${target}"
    cat "${SKILL_DIR}/copilot/instructions.md" >> "${target}"
    green "✓ Appended ez-appsec instructions to ${target}"
  else
    cp "${SKILL_DIR}/copilot/instructions.md" "${target}"
    green "✓ Created ${target}"
  fi
}

install_cursor() {
  mkdir -p ".cursor/rules"
  cp "${SKILL_DIR}/cursor/ez-appsec.md" ".cursor/rules/ez-appsec.md"
  green "✓ Cursor rule installed"
  echo "  Location : .cursor/rules/ez-appsec.md"
}

# ── uninstall functions ───────────────────────────────────────────────────────

uninstall() {
  local removed=0

  for f in "${GLOBAL_CLAUDE_DIR}/${SKILL_NAME}.md" "${GLOBAL_CLAUDE_DIR}/${INSTALL_SKILL_NAME}.md" "${GLOBAL_CLAUDE_DIR}/${PIPELINE_SCAN_SKILL_NAME}.md" "${GLOBAL_CLAUDE_DIR}/${UPDATE_VULNS_SKILL_NAME}.md" "${GLOBAL_CLAUDE_DIR}/${LOCAL_SCAN_SKILL_NAME}.md"; do
    if [[ -f "${f}" ]]; then
      rm "${f}"
      green "✓ Removed ${f}"
      removed=$((removed + 1))
    fi
  done

  for f in "${PROJECT_CLAUDE_DIR}/${SKILL_NAME}.md" "${PROJECT_CLAUDE_DIR}/${INSTALL_SKILL_NAME}.md" "${PROJECT_CLAUDE_DIR}/${PIPELINE_SCAN_SKILL_NAME}.md" "${PROJECT_CLAUDE_DIR}/${UPDATE_VULNS_SKILL_NAME}.md" "${PROJECT_CLAUDE_DIR}/${LOCAL_SCAN_SKILL_NAME}.md"; do
    if [[ -f "${f}" ]]; then
      rm "${f}"
      green "✓ Removed ${f}"
      removed=$((removed + 1))
    fi
  done

  if [[ -f ".cursor/rules/ez-appsec.md" ]]; then
    rm ".cursor/rules/ez-appsec.md"
    green "✓ Removed .cursor/rules/ez-appsec.md"
    removed=$((removed + 1))
  fi

  if [[ $removed -eq 0 ]]; then
    yellow "Nothing to uninstall."
  fi

  if [[ -f ".github/copilot-instructions.md" ]] && grep -q "ez-appsec" ".github/copilot-instructions.md" 2>/dev/null; then
    yellow "ℹ  .github/copilot-instructions.md contains ez-appsec content — remove manually if desired"
  fi
}

# ── argument parsing ──────────────────────────────────────────────────────────

MODE_GLOBAL=false
MODE_PROJECT=false
MODE_COPILOT=false
MODE_CURSOR=false
MODE_UNINSTALL=false

if [[ $# -eq 0 ]]; then
  MODE_GLOBAL=true
fi

while [[ $# -gt 0 ]]; do
  case $1 in
    --global)    MODE_GLOBAL=true ;;
    --project)   MODE_PROJECT=true ;;
    --copilot)   MODE_COPILOT=true ;;
    --cursor)    MODE_CURSOR=true ;;
    --all)       MODE_GLOBAL=true; MODE_COPILOT=true; MODE_CURSOR=true ;;
    --uninstall) MODE_UNINSTALL=true ;;
    -h|--help)   usage; exit 0 ;;
    *) red "Unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

# ── execute ───────────────────────────────────────────────────────────────────

if $MODE_UNINSTALL; then
  uninstall
  exit 0
fi

$MODE_GLOBAL  && install_claude_global
$MODE_PROJECT && install_claude_project
$MODE_COPILOT && install_copilot
$MODE_CURSOR  && install_cursor

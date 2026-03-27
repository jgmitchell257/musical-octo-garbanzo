#!/usr/bin/env bash
# =============================================================================
#  python_audit.sh — Python Package Security Audit Tool
#  Compatible with: Debian Linux (Ubuntu 20.04+, Debian 11+)
#
#  Usage:
#    chmod +x python_audit.sh
#    ./python_audit.sh --project "my-audit" --packages packages.txt [--guarddog] [--bandit]
#
#  pip-audit always runs. guarddog and bandit are optional.
#
#  packages.txt format (one package per line, optional version pin):
#    requests
#    flask==2.3.0
#    numpy>=1.24
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}";
            echo -e "${BOLD}${CYAN}  $*${RESET}";
            echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}\n"; }

# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────
AUDIT_DATE="$(date '+%Y-%m-%d %H:%M:%S %Z')"   # auto-detected — no user input needed
PROJECT_NAME=""
AUDITOR="$(whoami)"
PACKAGES_FILE=""
WORK_DIR=""            # set after args are parsed
RUN_DIR="$(pwd)"       # directory the script is invoked from — report is saved here

# Tool enable flags.  All default false; if NO tool switch is passed the
# run-all block below flips all three to true automatically.
RUN_GUARDDOG=false
RUN_BANDIT=false

# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF

${BOLD}Usage:${RESET}
  $0 --project <n> --auditor <n> --packages <FILE> [OPTIONS]

${BOLD}Required:${RESET}
  --project     Project / audit name (used for folder and report filename)
  --packages    Path to a .txt file listing packages to audit (one per line)

${BOLD}Optional:${RESET}
  --auditor     Auditor name (recorded in the report; defaults to logged-in user)

${BOLD}Tool Switches (optional — pip-audit always runs):${RESET}
  --guarddog    Run guarddog  (malicious code / supply-chain detection)
  --bandit      Run bandit    (static code security analysis)

${BOLD}Other Options:${RESET}
  -h, --help    Show this help message

${BOLD}packages.txt example:${RESET}
  requests
  flask==2.3.0
  numpy>=1.24

EOF
    exit 0
}

if [[ $# -eq 0 ]]; then usage; fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)   PROJECT_NAME="$2";  shift 2 ;;
        --auditor)   AUDITOR="$2";       shift 2 ;;
        --packages)  PACKAGES_FILE="$2"; shift 2 ;;
        --guarddog)  RUN_GUARDDOG=true;  shift   ;;
        --bandit)    RUN_BANDIT=true;    shift   ;;
        -h|--help)   usage ;;
        *) error "Unknown argument: $1"; usage ;;
    esac
done


# ─────────────────────────────────────────────────────────────────────────────
# Validate inputs
# ─────────────────────────────────────────────────────────────────────────────
MISSING=()
[[ -z "$PROJECT_NAME"  ]] && MISSING+=("--project")
[[ -z "$PACKAGES_FILE" ]] && MISSING+=("--packages")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    error "Missing required arguments: ${MISSING[*]}"
    usage
fi

if [[ ! -f "$PACKAGES_FILE" ]]; then
    error "Packages file not found: $PACKAGES_FILE"
    exit 1
fi

# Sanitise project name for use as a directory/file name
SAFE_NAME=$(echo "$PROJECT_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_.-')
WORK_DIR="${RUN_DIR}/${SAFE_NAME}"
REPORT_FILE="${RUN_DIR}/${SAFE_NAME}-audit.txt"   # <── saved in the invocation dir
PACKAGES_ABS="$(realpath "$PACKAGES_FILE")"


# ─────────────────────────────────────────────────────────────────────────────
# Prerequisite checks
# ─────────────────────────────────────────────────────────────────────────────
header "Prerequisite Checks"

check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        error "'$1' is not installed or not in PATH."
        echo -e "  Install hint: ${YELLOW}$2${RESET}"
        exit 1
    fi
    success "$1 found: $(command -v "$1")"
}

check_cmd "uv"      "curl -LsSf https://astral.sh/uv/install.sh | sh"
check_cmd "python3" "sudo apt install python3"

# ─────────────────────────────────────────────────────────────────────────────
# Read package list — required before project setup
# ─────────────────────────────────────────────────────────────────────────────
header "Reading Package List"

# Strip blank lines and comments
mapfile -t PACKAGES < <(grep -v '^\s*#' "$PACKAGES_ABS" | grep -v '^\s*$' || true)

if [[ ${#PACKAGES[@]} -eq 0 ]]; then
    error "No packages found in ${PACKAGES_ABS}"
    exit 1
fi

info "Packages to audit (${#PACKAGES[@]} total):"
for pkg in "${PACKAGES[@]}"; do
    echo "  • $pkg"
done

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Project Setup
# ─────────────────────────────────────────────────────────────────────────────
header "Step 1 — Project Setup"

TOOLS_TO_INSTALL=("pip-audit")
[[ "$RUN_GUARDDOG" == true ]] && TOOLS_TO_INSTALL+=("guarddog") || true
[[ "$RUN_BANDIT"   == true ]] && TOOLS_TO_INSTALL+=("bandit")   || true

if [[ ! -d "$WORK_DIR" ]]; then
    info "Project not found — creating new project: ${WORK_DIR}"

    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"

    info "Initialising uv project..."
    uv init --no-workspace --python python3 . 2>&1 | sed 's/^/  /'
    success "uv project initialised"

    info "Creating virtual environment..."
    uv venv .venv 2>&1 | sed 's/^/  /'
    success "Virtual environment created at ${WORK_DIR}/.venv"

    # shellcheck disable=SC1091
    source .venv/bin/activate
    success "Virtual environment activated"

    info "Installing audit tools: ${TOOLS_TO_INSTALL[*]}..."
    uv pip install --quiet "${TOOLS_TO_INSTALL[@]}" 2>&1 | sed 's/^/  /'
    success "Audit tools installed"

    info "Installing packages..."
    for pkg in "${PACKAGES[@]}"; do
        info "  Installing: ${pkg}"
        uv pip install "$pkg" 2>&1 | sed 's/^/  /' || warn "  Failed to install: ${pkg}"
    done
    success "Packages installed"
else
    info "Project exists — updating: ${WORK_DIR}"
    cd "$WORK_DIR"

    # shellcheck disable=SC1091
    source .venv/bin/activate
    success "Virtual environment activated"

    info "Updating audit tools..."
    uv pip install --quiet --upgrade "${TOOLS_TO_INSTALL[@]}" 2>&1 | sed 's/^/  /'
    success "Audit tools updated"

    info "Updating packages..."
    for pkg in "${PACKAGES[@]}"; do
        info "  Updating: ${pkg}"
        uv pip install --upgrade "$pkg" 2>&1 | sed 's/^/  /' || warn "  Failed to update: ${pkg}"
    done
    success "Packages updated"
fi

echo ""
info "Tool versions:"
for tool in guarddog bandit pip-audit; do
    ver=$(python3 -m pip show "$tool" 2>/dev/null | grep '^Version' | awk '{print $2}' || true)
    [[ -n "$ver" ]] && printf "  %-12s %s\n" "$tool" "$ver" || true
done

# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Run audits and write report
# ─────────────────────────────────────────────────────────────────────────────
header "Step 2 — Running Audits"

SCRIPT_START=$(date +%s)

report_divider() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_FILE"
}

report_section() {
    echo ""                  >> "$REPORT_FILE"
    report_divider
    echo "  $*"              >> "$REPORT_FILE"
    report_divider
    echo ""                  >> "$REPORT_FILE"
}

# Enabled-tools display line for the report header
ENABLED_TOOLS="pip-audit"
[[ "$RUN_GUARDDOG" == true ]] && ENABLED_TOOLS+=" guarddog" || true
[[ "$RUN_BANDIT"   == true ]] && ENABLED_TOOLS+=" bandit"   || true

# ── Report header ─────────────────────────────────────────────────────────────
cat > "$REPORT_FILE" <<REPORT_HEADER
████████████████████████████████████████████████████████████████████
  PyPI PACKAGE SECURITY AUDIT REPORT
████████████████████████████████████████████████████████████████████

  Project   : ${PROJECT_NAME}
  Auditor   : ${AUDITOR}
  Generated : ${AUDIT_DATE}
  Host      : $(hostname)
  Packages  : ${PACKAGES_ABS}

  Tools Enabled : ${ENABLED_TOOLS}
  Tool Versions :
$(for tool in guarddog bandit pip-audit; do
    ver=$(python3 -m pip show "$tool" 2>/dev/null | grep '^Version' | awk '{print $2}' || true)
    [[ -n "$ver" ]] && printf "    • %-12s %s\n" "$tool" "$ver"
  done)

  Packages audited (${#PACKAGES[@]}):
$(for pkg in "${PACKAGES[@]}"; do echo "    • $pkg"; done)

REPORT_HEADER
report_divider >> "$REPORT_FILE"

# ── Counters ──────────────────────────────────────────────────────────────────
TOTAL_PACKAGES=${#PACKAGES[@]}
GUARDDOG_ISSUES=0
BANDIT_ISSUES=0
PIPAUDIT_ISSUES=0

# ═════════════════════════════════════════════════════════════════════════════
# TOOL 1 — pip-audit (always runs)
# ═════════════════════════════════════════════════════════════════════════════
report_section "PIP-AUDIT — Known CVE / Vulnerability Check"

{
    echo "  pip-audit queries the OSV (Open Source Vulnerabilities) and PyPI"
    echo "  Advisory databases to find known CVEs in installed packages."
    echo ""
} >> "$REPORT_FILE"

info "  [pip-audit] Scanning installed packages against vulnerability databases..."

PIPAUDIT_OUT=$( { pip-audit --format=columns 2>&1; } || true )
echo "$PIPAUDIT_OUT" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

if echo "$PIPAUDIT_OUT" | grep -qiE "(PYSEC|vuln|CVE|critical|high|medium|found [1-9])"; then
    PIPAUDIT_ISSUES=1
    warn "  [pip-audit] ⚠ Vulnerabilities detected"
else
    success "  [pip-audit] ✓ No known CVEs found"
fi

# ═════════════════════════════════════════════════════════════════════════════
# TOOL 2 — guarddog (flag-controlled)
# ═════════════════════════════════════════════════════════════════════════════
if [[ "$RUN_GUARDDOG" == true ]]; then
    report_section "GUARDDOG — Malicious Package Detection"

    {
        echo "  guarddog scans for malicious code patterns, typosquatting, supply"
        echo "  chain attacks, obfuscated code, and suspicious install-time behaviour."
        echo ""
    } >> "$REPORT_FILE"

    for pkg in "${PACKAGES[@]}"; do
        # Strip version specifiers to get the bare package name
        pkg_name=$(echo "$pkg" | sed 's/[>=<!].*//' | tr -d ' ')

        info "  [guarddog] Scanning: ${pkg_name}"
        echo "── Package: ${pkg_name} ──────────────────────────────" >> "$REPORT_FILE"

        GUARDDOG_OUT=$( { guarddog pypi scan "$pkg_name" 2>&1; } || true )

        echo "$GUARDDOG_OUT" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"

        if echo "$GUARDDOG_OUT" | grep -qiE "(issue|critical|high|medium|warning|error|dangerous|malicious)"; then
            (( GUARDDOG_ISSUES++ )) || true
            warn "  [guarddog] ⚠ Findings detected for: ${pkg_name}"
        else
            success "  [guarddog] ✓ Clean: ${pkg_name}"
        fi
    done
else
    info "  [guarddog] Skipped (--guarddog not specified)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# TOOL 3 — bandit (flag-controlled)
# ═════════════════════════════════════════════════════════════════════════════
if [[ "$RUN_BANDIT" == true ]]; then
    report_section "BANDIT — Static Code Security Analysis"

    {
        echo "  bandit performs static analysis of Python source code looking for"
        echo "  dangerous calls, hardcoded secrets, insecure functions, and more."
        echo ""
    } >> "$REPORT_FILE"

    SITE_PKG_DIR=$( python3 -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || echo "" )

    if [[ -z "$SITE_PKG_DIR" || ! -d "$SITE_PKG_DIR" ]]; then
        warn "Could not locate site-packages; skipping bandit scan."
        echo "  [SKIPPED] Could not locate site-packages directory." >> "$REPORT_FILE"
    else
        info "  site-packages: ${SITE_PKG_DIR}"

        for pkg in "${PACKAGES[@]}"; do
            pkg_name=$(echo "$pkg" | sed 's/[>=<!].*//' | tr -d ' ' | tr '-' '_')
            pkg_path="${SITE_PKG_DIR}/${pkg_name}"

            # Some packages install under a slightly different directory name
            if [[ ! -d "$pkg_path" ]]; then
                pkg_path=$(find "$SITE_PKG_DIR" -maxdepth 1 -type d \
                            -iname "${pkg_name}*" ! -iname "*.dist-info" ! -iname "*.data" \
                            2>/dev/null | head -1 || true)
            fi

            echo "── Package: ${pkg_name} ──────────────────────────────" >> "$REPORT_FILE"

            if [[ -z "$pkg_path" || ! -d "$pkg_path" ]]; then
                warn "  [bandit] Package source not found in site-packages: ${pkg_name}"
                echo "  [SKIPPED] Package source directory not found in site-packages." >> "$REPORT_FILE"
                echo "" >> "$REPORT_FILE"
                continue
            fi

            info "  [bandit] Scanning: ${pkg_name} (${pkg_path})"

            BANDIT_OUT=$( { bandit -r "$pkg_path" -f txt 2>&1; } || true )
            echo "$BANDIT_OUT" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"

            if echo "$BANDIT_OUT" | grep -qE "Severity: (HIGH|MEDIUM)"; then
                (( BANDIT_ISSUES++ )) || true
                warn "  [bandit] ⚠ Findings detected for: ${pkg_name}"
            else
                success "  [bandit] ✓ No high/medium issues: ${pkg_name}"
            fi
        done
    fi
else
    info "  [bandit] Skipped (--bandit not specified)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Write summary to report
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_END=$(date +%s)
ELAPSED=$(( SCRIPT_END - SCRIPT_START ))

OVERALL_STATUS="CLEAN"
if (( GUARDDOG_ISSUES > 0 || BANDIT_ISSUES > 0 || PIPAUDIT_ISSUES > 0 )); then
    OVERALL_STATUS="FINDINGS DETECTED — REVIEW REQUIRED"
fi

report_section "AUDIT SUMMARY"
cat >> "$REPORT_FILE" <<SUMMARY
  Overall Status : ${OVERALL_STATUS}
  Duration       : ${ELAPSED}s
  Packages       : ${TOTAL_PACKAGES}
  Tools Run      : ${ENABLED_TOOLS}

  ┌─────────────────────────────────────────┬─────────────────┐
  │ Tool                                    │ Result          │
  ├─────────────────────────────────────────┼─────────────────┤
  │ guarddog  (malicious code detection)    │ $(if [[ "$RUN_GUARDDOG" == true ]]; then printf "%-15s" "${GUARDDOG_ISSUES} package(s)"; else printf "%-15s" "skipped"; fi) │
  │ bandit    (static code analysis)        │ $(if [[ "$RUN_BANDIT"   == true ]]; then printf "%-15s" "${BANDIT_ISSUES} package(s)";   else printf "%-15s" "skipped"; fi) │
  │ pip-audit (known CVE / advisory check)  │ $([[ $PIPAUDIT_ISSUES -eq 0 ]] && printf "%-15s" "None" || printf "%-15s" "See above") │
  └─────────────────────────────────────────┴─────────────────┘

  NOTE: Findings require manual review. A finding does not automatically
  mean a package is unsafe — context and severity must be evaluated.
  Escalate HIGH/CRITICAL findings before including packages in production.

SUMMARY
report_divider >> "$REPORT_FILE"
echo ""                                               >> "$REPORT_FILE"
echo "  End of report — ${SAFE_NAME}-audit.txt"       >> "$REPORT_FILE"
echo ""                                               >> "$REPORT_FILE"

# ─────────────────────────────────────────────────────────────────────────────
# Console summary
# ─────────────────────────────────────────────────────────────────────────────
header "Audit Complete"

echo -e "  ${BOLD}Overall Status :${RESET} $([ "$OVERALL_STATUS" = "CLEAN" ] && echo "${GREEN}${OVERALL_STATUS}${RESET}" || echo "${YELLOW}${OVERALL_STATUS}${RESET}")"
echo -e "  ${BOLD}Duration       :${RESET} ${ELAPSED}s"
echo -e "  ${BOLD}Packages       :${RESET} ${TOTAL_PACKAGES}"
echo ""
echo -e "  ${BOLD}Tool Results:${RESET}"
if [[ "$RUN_GUARDDOG" == true ]]; then
    echo -e "    guarddog  — $([ $GUARDDOG_ISSUES -eq 0 ] && echo "${GREEN}✓ No issues${RESET}" || echo "${YELLOW}⚠ ${GUARDDOG_ISSUES} package(s) flagged${RESET}")"
else
    echo -e "    guarddog  — ${CYAN}skipped${RESET}"
fi
if [[ "$RUN_BANDIT" == true ]]; then
    echo -e "    bandit    — $([ $BANDIT_ISSUES -eq 0 ]   && echo "${GREEN}✓ No high/medium issues${RESET}" || echo "${YELLOW}⚠ ${BANDIT_ISSUES} package(s) flagged${RESET}")"
else
    echo -e "    bandit    — ${CYAN}skipped${RESET}"
fi
echo -e "    pip-audit — $([ $PIPAUDIT_ISSUES -eq 0 ] && echo "${GREEN}✓ No known CVEs${RESET}" || echo "${YELLOW}⚠ Vulnerabilities found${RESET}")"
echo ""
echo -e "  ${BOLD}Report saved to:${RESET} ${REPORT_FILE}"
echo ""


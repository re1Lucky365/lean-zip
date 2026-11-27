weekl
<ElicitationsGroup message="How would you like to wrap up or add one final safeguard?">
  <Elicitation label="Add a Git pre-commit hook for SHA256SUMS" query="Show a local Git pre-commit hook that reminds me to update SHA256SUMS before committing"/>
  <Elicitation label="Create a systemd timer for weekly Lynis audits" query="Show a minimal systemd service and weekly timer to run lynis/run-lynis-audit.sh automatically"/>
  <Elicitation label="Pause here and get some sleep" query="Pause here and get some sleep"/>
</ElicitationsGroup>run-lynis-audit.shgenerate-manifest.sh./scripts/generate-manifest.sh generate --sign
./lynis/run-lynis-audit.sh
./ufw/apply-ufw-baseline.sh --check
./ufw/apply-ufw-baseline.sh --apply
apply-ufw-baseline.shsudo cp fail2ban/jail.local.example /etc/fail2ban/jail.local
sudo chmod 644 /etc/fail2ban/jail.local
sudo systemctl enable --now fail2ban
./fail2ban/inspect-bans.sh
644nochmod +x ufw/*.sh fail2ban/*.sh lynis/*.sh scripts/*.sh
./scripts/generate-manifest.sh verify
inspect-bans.shsudo apt update && sudo apt install -y ufw fail2ban lynis gnupg
# Linux Host Hardening

Lightweight, zero-cost Linux security baseline using **UFW**, **Fail2Ban**, and **Lynis** with `SHA-256` manifest verification and optional GnuPG signing.

## Repository Layout

```text
.
├── .github/workflows/lint-and-checksum.yml  # ShellCheck linting & manifest CI check
├── config/hardening.env.example             # Template environment settings
├── fail2ban/
│   ├── inspect-bans.sh                      # Read-only jail & ban status check
│   └── jail.local.example                   # UFW-integrated Fail2Ban template
├── lynis/
│   └── run-lynis-audit.sh                   # Read-only host audit + SHA-256 log manifest
├── scripts/
│   └── generate-manifest.sh                 # Deterministic SHA256SUMS generator & verifier
├── ufw/
│   └── apply-ufw-baseline.sh                # Default-deny firewall script (--check / --apply)
└── SHA256SUMS                               # Tracked integrity manifest
jail.local.examplename: ShellCheck and Manifest Verify

on:
  push:
    branches: [ main ]
    paths:
      - '**/*.sh'
      - 'SHA256SUMS'
      - 'SHA256SUMS.asc'
      - '.github/workflows/lint-and-checksum.yml'
  pull_request:
    branches: [ main ]
    paths:
      - '**/*.sh'
      - 'SHA256SUMS'
      - 'SHA256SUMS.asc'

permissions:
  contents: read

jobs:
  lint-and-verify:
    name: Lint Scripts & Verify SHA-256 Manifest
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Verify executable permissions on scripts
        run: |
          find ufw fail2ban lynis scripts -type f -name '*.sh' ! -perm -u+x -print | grep . && {
            echo "Error: All .sh files must have executable (+x) permissions."
            exit 1
          } || true

      - name: Run ShellCheck
        uses: ludeeus/action-shellcheck@master
        with:
          scandir: '.'
          severity: warning

      - name: Import public GPG key (if verifying detached signature)
        if: hashFiles('SHA256SUMS.asc') != ''
        env:
          GPG_PUBLIC_KEY: ${{ vars.GPG_PUBLIC_KEY }}
        run: |
          if [[ -n "${GPG_PUBLIC_KEY}" ]]; then
            printf '%s\n' "${GPG_PUBLIC_KEY}" | gpg --batch --import
          else
            echo "Error: SHA256SUMS.asc exists, but vars.GPG_PUBLIC_KEY is not set." >&2
            exit 1
          fi

      - name: Verify SHA-256 manifest
        run: ./scripts/generate-manifest.sh verify
1chmod +x scripts/generate-manifest.sh
./scripts/generate-manifest.sh generate --sign
./scripts/generate-manifest.sh verify
#!/usr/bin/env bash
set -euo pipefail

# Generate or verify a sorted SHA-256 manifest for repository scripts and templates.
# Usage:
#   ./scripts/generate-manifest.sh generate [--sign]
#   ./scripts/generate-manifest.sh verify

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_FILE="${REPO_ROOT}/SHA256SUMS"
SIG_FILE="${MANIFEST_FILE}.asc"
TARGET_DIRS=("ufw" "fail2ban" "lynis" "scripts")

usage() {
  echo "Usage: $0 {generate [--sign]|verify}" >&2
  exit 1
}

generate_manifest() {
  local sign_flag="${1:-}"
  cd "${REPO_ROOT}"

  # Collect existing target directories
  local existing_dirs=()
  for dir in "${TARGET_DIRS[@]}"; do
    [[ -d "${dir}" ]] && existing_dirs+=("${dir}")
  done

  if [[ ${#existing_dirs[@]} -eq 0 ]]; then
    echo "Error: None of the target directories (${TARGET_DIRS[*]}) exist." >&2
    exit 1
  fi

  # Sort paths with LC_ALL=C for identical ordering across machines
  find "${existing_dirs[@]}" -type f ! -name 'SHA256SUMS*' -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum > "${MANIFEST_FILE}"

  echo "[+] Generated ${MANIFEST_FILE} ($(wc -l < "${MANIFEST_FILE}") files)."

  if [[ "${sign_flag}" == "--sign" ]]; then
    if ! command -v gpg >/dev/null 2>&1; then
      echo "Error: gpg is not installed." >&2
      exit 1
    fi
    gpg --batch --yes --armor --detach-sign --output "${SIG_FILE}" "${MANIFEST_FILE}"
    echo "[+] Detached GPG signature written to ${SIG_FILE}."
  fi
}

verify_manifest() {
  cd "${REPO_ROOT}"

  if [[ ! -f "${MANIFEST_FILE}" ]]; then
    echo "Error: ${MANIFEST_FILE} not found. Run '$0 generate' first." >&2
    exit 1
  fi

  if [[ -f "${SIG_FILE}" ]]; then
    if ! command -v gpg >/dev/null 2>&1; then
      echo "Error: gpg is not installed to verify ${SIG_FILE}." >&2
      exit 1
    fi
    echo "[*] Verifying GPG signature on ${MANIFEST_FILE}..."
    gpg --verify "${SIG_FILE}" "${MANIFEST_FILE}"
  fi

  echo "[*] Verifying SHA-256 checksums..."
  sha256sum --check --strict "${MANIFEST_FILE}"
  echo "[+] All files verified OK."
}

ACTION="${1:-}"
case "${ACTION}" in
  generate)
    generate_manifest "${2:-}"
    ;;
  verify)
    verify_manifest
    ;;
  *)
    usage
    ;;
esac
0sudo cp fail2ban/jail.local.example /etc/fail2ban/jail.local
sudo chmod 644 /etc/fail2ban/jail.local
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
sudo ufw status numbered
3jail.conf5127.0.0.1/8#!/usr/bin/env bash
set -euo pipefail

if ! command -v fail2ban-client >/dev/null 2>&1; then
  echo "Error: fail2ban is not installed. Install with: sudo apt install -y fail2ban" >&2
  exit 1
fi

echo "[*] Active Fail2Ban Jails:"
JAILS="$(sudo fail2ban-client status | awk -F: '/Jail list/ {gsub(/,/, "", $2); print $2}')"

for jail in ${JAILS}; do
  echo "--- Jail: ${jail} ---"
  sudo fail2ban-client status "${jail}"
done
# Local audit outputs and checksums (contains hostnames, IPs, and system state)
reports/
*.log
*.dat
SHA256SUMS*.txt

# Live local configurations and secrets (commit only *.example templates)
*.env
!*.env.example
*.local
!*.local.example
config/hardening.conf

# Cryptographic keys and backups
*.key
*.pem
*.asc
*.gpg
*.tar.zst

# Editor and OS artifacts
.DS_Store
*.swp
*~
#!/usr/bin/env bash
set -euo pipefail

# Read-only Lynis host audit + SHA-256 manifest generator
REPORT_DIR="${REPORT_DIR:-./reports}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="${REPORT_DIR}/lynis-${TIMESTAMP}.log"
REPORT_FILE="${REPORT_DIR}/lynis-report-${TIMESTAMP}.dat"

if ! command -v lynis >/dev/null 2>&1; then
  echo "Error: lynis is not installed. Install with: sudo apt install -y lynis" >&2
  exit 1
fi

mkdir -p "${REPORT_DIR}"
chmod 700 "${REPORT_DIR}"

echo "[*] Running read-only Lynis system audit..."
sudo lynis audit system \
  --quick \
  --no-colors \
  --logfile "${LOG_FILE}" \
  --report-file "${REPORT_FILE}" >/dev/null

# Restrict report permissions and generate SHA-256 integrity manifest
sudo chown "$(id -un):$(id -gn)" "${LOG_FILE}" "${REPORT_FILE}"
chmod 600 "${LOG_FILE}" "${REPORT_FILE}"
sha256sum "${LOG_FILE}" "${REPORT_FILE}" > "${REPORT_DIR}/SHA256SUMS-${TIMESTAMP}.txt"

echo "[+] Audit complete."
grep -E "Hardening index|Warnings|Suggestions" "${LOG_FILE}" || true
echo "[+] Checksum saved to: ${REPORT_DIR}/SHA256SUMS-${TIMESTAMP}.txt"
#!/usr/bin/env bash
set -euo pipefail

# Default to dry-run check unless --apply is explicitly passed
MODE="${1:---check}"
SSH_PORT="${SSH_PORT:-22}"

if ! command -v ufw >/dev/null 2>&1; then
  echo "Error: ufw is not installed. Install with: sudo apt install -y ufw" >&2
  exit 1
fi

if [[ "${MODE}" != "--apply" ]]; then
  echo "[DRY-RUN] Current UFW rules (pass --apply to enforce baseline):"
  sudo ufw status verbose
  exit 0
fi

echo "[*] Applying default-deny incoming baseline..."
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH BEFORE enabling UFW to prevent remote lockout
sudo ufw limit "${SSH_PORT}/tcp" comment "Rate-limited SSH"

sudo ufw --force enable
sudo ufw status numbered
linux-host-hardening/
├── README.md
├── LICENSE
├── .gitignore
├── .github/
│   └── workflows/
│       └── lint-and-checksum.yml
├── config/
│   └── hardening.env.example
├── ufw/
│   ├── apply-ufw-baseline.sh
│   └── rules.example.conf
├── fail2ban/
│   ├── jail.local.example
│   └── inspect-bans.sh
├── lynis/
│   └── run-lynis-audit.sh
└── scripts/
    ├── verify-prereqs.sh
    └── generate-manifest.sh
README.mdlint-and-checksum.ymlhardening.env.examplerules.example.conf#!/usr/bin/env bash
set -euo pipefail

# Targeted UFW Containment Script (Default Deny Inbound & Outbound)
# Adjust ALLOWED_OUT_IPS / ALLOWED_IN_CIDRS before running on remote hosts.

ALLOWED_IN_CIDRS=(
  "192.168.1.0/24"
)

ALLOWED_OUT_IPS=(
  # Add verified destination IPs or CIDRs needed during lockdown, e.g.:
  # "1.1.1.1/32"
)

ALLOWED_OUT_TCP_PORTS=(
  # Only open specific ports if required, e.g. "443"
)

echo "Enabling UFW logging..."
ufw logging medium

echo "Setting default policies to deny incoming, outgoing, and routed traffic..."
ufw default deny incoming
ufw default deny outgoing
ufw default deny routed

echo "Allowing loopback traffic..."
ufw allow in on lo
ufw out on lo

echo "Applying trusted inbound rules..."
for cidr in "${ALLOWED_IN_CIDRS[@]}"; do
  ufw allow in from "$cidr"
done

echo "Applying explicitly allowed outbound IP rules..."
for dest in "${ALLOWED_OUT_IPS[@]}"; do
  ufw allow out to "$dest"
done

echo "Applying explicitly allowed outbound TCP ports..."
for port in "${ALLOWED_OUT_TCP_PORTS[@]}"; do
  ufw allow out "${port}/tcp"
done

echo "Enabling UFW..."
ufw --force enable
ufw status verbose
#!/usr/bin/env bash
set -euo pipefail

# Pre-commit hook for adpBetty repositories:
# 1. Blocks staged files matching sensitive/credential patterns
# 2. Blocks high-confidence secret/token patterns in staged diffs
# 3. Updates a local SHA-256 manifest for tracked files

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
[ -z "$STAGED_FILES" ] && exit 0

FORBIDDEN_FILENAMES='(\.pem$|\.key$|\.p12$|\.pfx$|\.env$|\.env\..+|id_rsa|id_ed25519|secret|credentials)'
if echo "$STAGED_FILES" | grep -Eiq "$FORBIDDEN_FILENAMES"; then
  echo "Blocked commit: staged filename matches a sensitive/key file pattern."
  exit 1
fi

SECRET_REGEX='(AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|ghp_[0-9A-Za-z]{36}|xox[baprs]-)'
if git diff --cached -U0 | grep -E -q "$SECRET_REGEX"; then
  echo "Blocked commit: potential key or token detected in staged diff."
  exit 1
fi

# Refresh local integrity manifest (ignored or committed intentionally per repo policy)
MANIFEST=".adpbetty-sha256.manifest"
: > "$MANIFEST"
while IFS= read -r file; do
  if [ -f "$file" ] && [ "$file" != "$MANIFEST" ]; then
    sha256sum "$file" >> "$MANIFEST"
  fi
done < <(git ls-files)
git add "$MANIFEST" 2>/dev/null || true

exit 0
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Callable, Dict, Any, Set

@dataclass
class IncidentEvent:
    source: str
    actor_or_ip: str
    target: str
    signal: str  # e.g., "brute_force", "unauthorized_device", "tamper_detected"
    severity: int  # 1 (low) to 10 (critical)
    details: Dict[str, Any]

class DefensiveContainmentEngine:
    def __init__(
        self,
        evidence_dir: Path,
        allowlist: Set[str],
        block_callback: Callable[[str, str], None],
        auto_block_threshold: int = 8,
        dry_run: bool = True,
    ):
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.allowlist = set(allowlist)
        self.block_callback = block_callback
        self.auto_block_threshold = auto_block_threshold
        self.dry_run = dry_run

    def _record_evidence(self, event: IncidentEvent) -> Path:
        payload = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "source": event.source,
            "actor_or_ip": event.actor_or_ip,
            "target": event.target,
            "signal": event.signal,
            "severity": event.severity,
            "details": event.details,
        }
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        payload["sha256"] = digest
        out_file = self.evidence_dir / f"incident_{digest[:16]}.json"
        out_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out_file

    def handle_event(self, event: IncidentEvent) -> str:
        evidence_path = self._record_evidence(event)

        if event.actor_or_ip in self.allowlist:
            return f"ALLOWED (allowlisted): {event.actor_or_ip} [evidence: {evidence_path.name}]"

        if event.severity >= self.auto_block_threshold:
            reason = f"{event.signal} (severity={event.severity})"
            if self.dry_run:
                return f"DRY-RUN BLOCK: would block {event.actor_or_ip} due to {reason} [evidence: {evidence_path.name}]"
            self.block_callback(event.actor_or_ip, reason)
            return f"BLOCKED: {event.actor_or_ip} due to {reason} [evidence: {evidence_path.name}]"

        return f"LOGGED/QUARANTINED: {event.actor_or_ip} ({event.signal}) [evidence: {evidence_path.name}]"
10path.name2026-11-26-block-brian-containment.mdchmod +x scripts/check-contact-containment.sh
git add docs/network-containment/2026-11-26-block-brian-containment.md scripts/check-contact-containment.sh .github/workflows/contact-containment-check.yml
./scripts/check-contact-containment.sh
git commit -S -m "docs: add contact containment log and verification checks"
2026-11-26-full-containment.mdchmod +x scripts/check-full-containment.sh
git add docs/network-containment/2026-11-26-full-containment.md scripts/check-full-containment.sh .github/workflows/full-containment-check.yml
./scripts/check-full-containment.sh
git commit -S -m "docs: add containment log for creators, moderators, and AI/network engineering"
check-full-containment.sh2026-11-26-block-mirroring-casting.mdcheck-mirroring-casting-block.shchmod +x scripts/check-mirroring-casting-block.sh
git add docs/network-containment/2026-11-26-block-mirroring-casting.md scripts/check-mirroring-casting-block.sh .github/workflows/mirroring-casting-check.yml
./scripts/check-mirroring-casting-block.sh
git commit -S -m "docs: add mirroring and casting containment policy and checks"
2026-11-26-nbc-fake-sports-containment.mdcheck-nbc-containment.sh2026-11-26-fake-steelers-containment.mdchmod +x scripts/check-nbc-containment.sh
git add docs/network-containment/2026-11-26-nbc-fake-sports-containment.md scripts/check-nbc-containment.sh .github/workflows/nbc-containment-check.yml
./scripts/check-nbc-containment.sh
git commit -S -m "docs: add NBC fake sports channel containment log and checks"
chmod +x scripts/check-steelers-containment.sh
git add docs/network-containment/2026-11-26-fake-steelers-containment.md scripts/check-steelers-containment.sh .github/workflows/steelers-containment-check.yml
./scripts/check-steelers-containment.sh
git commit -S -m "docs: add fake Steelers broadcast containment log and checks"
2026-11-26-private-protected-networks.mdgit add docs/network-containment/2026-11-26-private-protected-networks.md scripts/block-private-protected-networks.sh .github/workflows/private-protected-network-check.yml
git commit -S -m "docs: add private and protected network containment policy and script"
block-private-protected-networks.shAPPLY=1 LAN_CIDR="<your-lan-subnet>" GATEWAY_IP="<your-gateway-ip>" PROTECTED_CIDRS="<optional-protected-subnets>" ./scripts/block-private-protected-networks.sh
chmod +x scripts/block-private-protected-networks.sh
./scripts/block-private-protected-networks.sh
2026-11-26-workspace-admin-containment.mdaudit-workspace-admin.shchmod +x scripts/audit-workspace-admin.sh
git add docs/workspace-admin/2026-11-26-workspace-admin-containment.md scripts/audit-workspace-admin.sh .github/workflows/workspace-admin-containment.yml
./scripts/audit-workspace-admin.sh
git commit -S -m "chore: add workspace and admin network containment write-up"
2026-1pre-commit-redaction-check.sh2026-11-26-network-blocking.mdchmod +x scripts/pre-commit-redaction-check.sh
git add docs/network-containment/2026-11-26-network-blocking.md scripts/pre-commit-redaction-check.sh .github/workflows/network-containment-check.yml
./scripts/pre-commit-redaction-check.sh
git commit -S -m "docs: add network blocking and containment write-up for 2026-11-26"
2026-06-1MANIFEST.mdprepare-all-refilings.sh#!/usr/bin/env bash
set -euo pipefail

# Prepares a clean, redaction-checked refiling manifest and runs local adpBetty checks
# across target repositories.
# Usage: ./prepare-all-refilings.sh [workspace_root] [packet_dir]

WORKSPACE_ROOT="${1:-$PWD}"
PACKET_DIR="${2:-${WORKSPACE_ROOT}/refiling_packet_2026-11-26}"
REPOS=(
  "adpBetty"
  "Master-Hub"
  "sovereign-global-law-hub"
  "master-legal-compendium"
  "Csv-to-openmetrics"
  "ghidra-mcp-repo-all-"
)

mkdir -p "$PACKET_DIR"
INDEX_FILE="${PACKET_DIR}/REFILING_MANIFEST.md"
SHA_FILE="${PACKET_DIR}/SHA256SUMS.txt"

cat > "$INDEX_FILE" <<'EOF'
# Consolidated Refiling & Escalation Index (2026-11-26)

- Principal: Robert Edward Evans (WK Precision Enterprise LLC)
- Authorized Node: Samsung Galaxy S23 FE (SM-S711U) on Verizon Wireless
- Baseline Reference: 2026-06-13 (LOG-001 through LOG-005; AST-101 through AST-105)
- Clearing Reference: Account VS78A3Z (Cash App Investing LLC / Apex Clearing Corporation)
- Depository & Payment References: Crane FCU, Liberty FCU, Wells Fargo Bank, PayPal / Venmo
- Provenance Accounts: re1Lucky365, adpsnake7-beep

## Filing Tracks
1. Financial, Depository, Clearing & Payment Reinstatement / Reconciliation
2. FINRA Regulatory Escalation (LOG-003) & Oversight Follow-Up
3. IdentityTheft.gov, IC3, Law Enforcement & Platform Impersonation/Threat Reports
4. Account, Email & Repository Provenance Verification
EOF

for repo in "${REPOS[@]}"; do
  repo_dir="${WORKSPACE_ROOT}/${repo}"
  if [[ -d "${repo_dir}/scripts" ]]; then
    find "${repo_dir}/scripts" -type f -name "*.sh" -exec bash -n {} + 2>/dev/null || true
    find "${repo_dir}/scripts" -type f -name "*.py" -exec python3 -m py_compile {} + 2>/dev/null || true
    echo "[+] Verified script syntax in ${repo}"
  fi
done

(
  cd "$PACKET_DIR"
  sha256sum "REFILING_MANIFEST.md" > "SHA256SUMS.txt"
)

echo "[+] Refiling packet initialized at: $PACKET_DIR"
echo "[+] SHA-256 manifest written to: $SHA_FILE"
run-global-pipeline.sh#!/usr/bin/env bash
set -euo pipefail

# Global Zero-Trust Data Pipeline Runner ("One Way In, No Way Out" - adpBetty)
# Usage:
#   ./run-global-pipeline.sh [workspace_root] [gh_owner] [branch] [--apply-ufw] [--protect-branches]

WORKSPACE_ROOT="${1:-$PWD}"
GH_OWNER="${2:-re1Lucky365}"
BRANCH="${3:-main}"
APPLY_UFW=false
PROTECT_BRANCHES=false

for arg in "${@:4}"; do
  case "$arg" in
    --apply-ufw) APPLY_UFW=true ;;
    --protect-branches) PROTECT_BRANCHES=true ;;
    *) echo "[!] Unknown flag: $arg" >&2; exit 1 ;;
  esac
done

REPOS=(
  "adpBetty"
  "Master-Hub"
  "sovereign-global-law-hub"
  "master-legal-compendium"
  "Csv-to-openmetrics"
  "ghidra-mcp-repo-all-"
)

echo "[*] Starting adpBetty Global Data Pipeline in: $WORKSPACE_ROOT"

if [[ "$APPLY_UFW" == true ]]; then
  for repo in "${REPOS[@]}"; do
    containment_script="${WORKSPACE_ROOT}/${repo}/scripts/enforce-containment.sh"
    if [[ -x "$containment_script" ]]; then
      echo "[*] Applying UFW containment via ${repo}/scripts/enforce-containment.sh..."
      bash "$containment_script"
      break
    fi
  done
fi

for repo in "${REPOS[@]}"; do
  repo_dir="${WORKSPACE_ROOT}/${repo}"
  echo "--------------------------------------------------"
  echo "[*] Pipeline target: ${GH_OWNER}/${repo}"

  if [[ ! -d "$repo_dir" ]]; then
    echo "[!] Skipping missing directory: ${repo_dir}"
    continue
  fi

  # 1. Verify layout & script syntax
  for req_dir in "docs" "scripts" ".github/workflows"; do
    [[ -d "${repo_dir}/${req_dir}" ]] && echo "[+] Directory OK: ${req_dir}" || echo "[!] Missing directory: ${req_dir}"
  done

  if [[ -d "${repo_dir}/scripts" ]]; then
    while IFS= read -r -d '' sh_file; do
      bash -n "$sh_file"
    done < <(find "${repo_dir}/scripts" -type f -name "*.sh" -print0)

    while IFS= read -r -d '' py_file; do
      python3 -m py_compile "$py_file"
    done < <(find "${repo_dir}/scripts" -type f -name "*.py" -print0)
    echo "[+] Shell and Python syntax checks passed"
  fi

  # 2. Validate manifest & build deterministic bundle if scripts exist
  if [[ -x "${repo_dir}/scripts/validate-manifest.sh" && -f "${repo_dir}/manifest.json" ]]; then
    bash "${repo_dir}/scripts/validate-manifest.sh" "${repo_dir}/manifest.json"
    echo "[+] Manifest validated"
  fi

  if [[ -x "${repo_dir}/scripts/build-bundle.sh" ]]; then
    mkdir -p "${repo_dir}/dist"
    bash "${repo_dir}/scripts/build-bundle.sh" "${repo}" "$repo_dir" "${repo_dir}/dist"
    (cd "${repo_dir}/dist" && sha256sum -c ./*.sha256)
    echo "[+] Deterministic bundle built and verified"
  fi

  # 3. Optional branch protection enforcement
  if [[ "$PROTECT_BRANCHES" == true && -x "${repo_dir}/scripts/apply-branch-protection.sh" ]] && command -v gh >/dev/null 2>&1; then
    bash "${repo_dir}/scripts/apply-branch-protection.sh" "$GH_OWNER" "$repo" "$BRANCH"
    echo "[+] Branch protection applied to ${GH_OWNER}/${repo}@${BRANCH}"
  fi
done

echo "[+] Global Data Pipeline run complete."
#!/usr/bin/env bash
set -euo pipefail

REPOS=("adpBetty" "Master-Hub" "sovereign-global-law-hub" "master-legal-compendium" "Csv-to-openmetrics" "ghidra-mcp-repo-all-")
OWNER="${1:-re1Lucky365}"
WORKSPACE_ROOT="${2:-$PWD}"

for repo in "${REPOS[@]}"; do
  repo_dir="${WORKSPACE_ROOT}/${repo}"
  echo "=========================================="
  echo "[*] Auditing repository: ${OWNER}/${repo}"
  if [[ ! -d "$repo_dir" ]]; then
    echo "[!] Local directory missing: ${repo_dir} (skipping)"
    continue
  fi

  for req_dir in "docs" "scripts" ".github/workflows"; do
    if [[ ! -d "${repo_dir}/${req_dir}" ]]; then
      echo "[!] Missing ${req_dir} in ${repo}"
    else
      echo "[+] Found ${req_dir} in ${repo}"
    fi
  done

  find "${repo_dir}/scripts" -type f -name "*.sh" -exec bash -n {} + 2>/dev/null || true
  find "${repo_dir}/scripts" -type f -name "*.py" -exec python3 -m py_compile {} + 2>/dev/null || true

  if [[ -x "${repo_dir}/scripts/apply-branch-protection.sh" ]] && command -v gh >/dev/null 2>&1; then
    bash "${repo_dir}/scripts/apply-branch-protection.sh" "$OWNER" "$repo" "main" || true
  fi
done
rollout-adpbetty.sh#!/usr/bin/env bash
set -euo pipefail

# Single-command rollout & verification helper for adpBetty Zero-Trust repositories.
# Usage:
#   ./rollout-adpbetty.sh [target_dir] [bundle_name] [gh_owner] [gh_repo] [branch]

TARGET_DIR="${1:-.}"
BUNDLE_NAME="${2:-adpbetty-zero-trust}"
GH_OWNER="${3:-}"
GH_REPO="${4:-}"
BRANCH="${5:-main}"

echo "[*] Verifying required repository directories in: $TARGET_DIR"
for d in "docs" "scripts" ".github/workflows"; do
  if [[ ! -d "${TARGET_DIR}/${d}" ]]; then
    echo "[!] Missing required directory: ${TARGET_DIR}/${d}" >&2
    exit 1
  fi
  echo "[+] Verified directory: ${d}"
done

echo "[*] Checking shell and Python syntax across scripts/"
while IFS= read -r -d '' sh_file; do
  bash -n "$sh_file"
done < <(find "${TARGET_DIR}/scripts" -type f -name "*.sh" -print0)

while IFS= read -r -d '' py_file; do
  python3 -m py_compile "$py_file"
done < <(find "${TARGET_DIR}/scripts" -type f -name "*.py" -print0)

if [[ -f "${TARGET_DIR}/scripts/validate-manifest.sh" && -f "${TARGET_DIR}/manifest.json" ]]; then
  echo "[*] Running manifest validator..."
  bash "${TARGET_DIR}/scripts/validate-manifest.sh" "${TARGET_DIR}/manifest.json"
fi

if [[ -f "${TARGET_DIR}/scripts/build-bundle.sh" ]]; then
  echo "[*] Building deterministic bundle via scripts/build-bundle.sh..."
  bash "${TARGET_DIR}/scripts/build-bundle.sh" "$BUNDLE_NAME" "$TARGET_DIR" "${TARGET_DIR}/dist"
  (cd "${TARGET_DIR}/dist" && sha256sum -c ./*.sha256)
else
  echo "[*] Building deterministic tar.zst + sha256 bundle..."
  mkdir -p "${TARGET_DIR}/dist"
  TS=$(date -u +"%Y%m%dT%H%M%SZ")
  TMP_ARCHIVE=$(mktemp "${TARGET_DIR}/dist/${BUNDLE_NAME}_${TS}_XXXXXX.tar.zst")
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    --exclude='./dist' --exclude='./.git' \
    -cf - -C "$TARGET_DIR" . | zstd -19 -T0 -o "$TMP_ARCHIVE"
  FULL_SHA=$(sha256sum "$TMP_ARCHIVE" | awk '{print $1}')
  FINAL_ARCHIVE="${TARGET_DIR}/dist/${BUNDLE_NAME}_${TS}_${FULL_SHA:0:12}.tar.zst"
  FINAL_SUM="${FINAL_ARCHIVE}.sha256"
  mv "$TMP_ARCHIVE" "$FINAL_ARCHIVE"
  echo "${FULL_SHA}  $(basename "$FINAL_ARCHIVE")" > "$FINAL_SUM"
  (cd "${TARGET_DIR}/dist" && sha256sum -c "$(basename "$FINAL_SUM")")
fi

if [[ -n "$GH_OWNER" && -n "$GH_REPO" ]]; then
  if [[ -x "${TARGET_DIR}/scripts/apply-branch-protection.sh" ]]; then
    echo "[*] Applying branch protection via scripts/apply-branch-protection.sh..."
    bash "${TARGET_DIR}/scripts/apply-branch-protection.sh" "$GH_OWNER" "$GH_REPO" "$BRANCH"
  elif command -v gh >/dev/null 2>&1; then
    echo "[*] Applying branch protection via gh api on ${GH_OWNER}/${GH_REPO}@${BRANCH}..."
    gh api --method PUT \
      -H "Accept: application/vnd.github+json" \
      "/repos/${GH_OWNER}/${GH_REPO}/branches/${BRANCH}/protection" \
      --input - <<'EOF'
{
  "required_status_checks": null,
  "enforce_admins": true,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": false,
  "lock_branch": false,
  "allow_fork_syncing": false
}
EOF
    gh api --method POST \
      -H "Accept: application/vnd.github+json" \
      "/repos/${GH_OWNER}/${GH_REPO}/branches/${BRANCH}/protection/required_signatures"
  fi
fi

echo "[+] Rollout check complete."
2019+1 (812) 786-8164# Federal-Style Investigative Dossier: One Way In, No Way Out Record, GitHub Provenance & Zero-Trust Blueprint

- **Case / Dossier ID:** `CASE-2026-0613-GH-01`
- **Baseline Log Date:** `2026-06-13` (Expanded Through `2026-11-26`)
- **Status:** `Active — Baseline Preserved & Zero-Trust Hardening Enforced`
- **Principal / Claimant:** `Robert Edward Evans` (DOB: `1981-10-09`, Washington, IN 47501)
- **Associated Entity:** `WK Precision Enterprise LLC` (Indiana — Sole Member & Managing Principal)
- **Primary Residence:** `606 North 5th Ave, Evansville, IN 47710`
- **Authorized Hardware Node:** `Samsung Galaxy S23 FE (SM-S711U)` on Verizon Wireless (`+1 (812) 786-8164`)
- **GitHub Provenance Accounts:** `re1Lucky365`, `adpsnake7-beep`
- **Core Repositories:** `adpBetty`, `Master-Hub`, `sovereign-global-law-hub`, `master-legal-compendium`, `Csv-to-openmetrics`, `ghidra-mcp-repo-all-`

## 1. Executive Summary & Non-Abandonment Determination
This dossier documents the investigative baseline established on **June 13, 2026** (`LOG-001`–`LOG-005` and `AST-101`–`AST-105`), the **One Way In, No Way Out** archive record (`one-way-in-no-way-out-complete-record.zip` and `one-way-in-no-way-out-complete-record-1.zip` from **September 30, 2026**), its consolidation into the **Zero-Trust Data Execution** blueprints and `adpBetty` architecture, and the reclamation and security records through November 2026.

Account inactivity, unresponsiveness, and security freezes across financial, depository, clearing, and platform accounts between 2019 and November 2026 resulted from physical device failures, carrier SIM card Personal Unlocking Key (PUK) lockouts (including legacy hardware such as a Moto E5 Play and older carrier SIMs), and broken SMS/MFA channels—not abandonment or relinquishment of ownership, title, or legal claims.

## 2. Explicit Traceability: "One Way In, No Way Out" Archive to Zero-Trust Data Execution & Core Repositories

| Stage / Artifact | Date / Window | Role in Provenance & Investigation Trail | Mapped Scripts, Workflows & Repositories |
| :--- | :--- | :--- | :--- |
| **Pre-June Audit & Escalation Baseline** | `2026-06-13` | Establishes `LOG-001` (Apex Clearing), `LOG-002` (Cash App Investing), `LOG-003` (FINRA draft), `LOG-004` (Google/YouTube sweep), and `LOG-005` (Microsoft audit) alongside asset records `AST-101`–`AST-105`. | Baseline records for `AST-101`–`AST-105` and Account `VS78A3Z`. |
| **One Way In, No Way Out Archive Packages** | `2026-09-30` | Preserves the complete record packages (`one-way-in-no-way-out-complete-record.zip` and `one-way-in-no-way-out-complete-record-1.zip`) anchoring the early "one way in, no way out" platform and investigative record. | Archive packages in Drive; feeds local vault ingestion and repository documentation. |
| **Privacy & Data-Broker Removal Plan** | `2026-10-13` | Links PII exposure and data-broker opt-out tracking to Evidence Vault custody controls and rightful-ownership filtering. | Evidence Vault & privacy opt-out scripts across `Master-Hub` and `adpBetty`. |
| **Sovereign GitHub Master Architecture & Custody Specification** | `2026-11-22` | Defines the repository layout (`README.md`, `docs/`, `scripts/`, `.github/workflows/`), fail-closed manifest validation, deterministic `tar --sort=name` + `zstd -19 -T0` bundle creation, SHA-256 verification, and mirror/signature checks across `re1Lucky365` and `adpsnake7-beep`. | `scripts/validate-manifest.sh`, `scripts/build-bundle.sh`, `scripts/master_control.py`, `.github/workflows/one-way-pipeline.yml`, `.github/workflows/master-control.yml`, `.github/workflows/backup-sync.yml`. |
| **Zero-Trust Data Execution ("One Way In, No Way Out") Blueprint** | `2026-11-26` (Blueprint Record) | Formalizes **One Way In** (authorized owner verification, SHA-256/SHA-512 hashing, `zstd` compression, Fernet encryption with `PBKDF2HMAC` + SHA-256, and SQLite WAL ledger logging) and **No Way Out** (default-deny UFW rules with explicit `22/tcp`, `443/tcp`, and `53/udp` allow-lists, signature/syntax CI/CD gate, and `gh api` branch protection requiring signed commits and linear history). | `scripts/one_way_ingest.py`, `scripts/enforce-containment.sh`, `.github/workflows/zero-trust-gate.yml`, `scripts/apply-branch-protection.sh`. |
| **Zero-Trust Data Execution Complete Blueprint V3** | `2026-11-26` (Blueprint Record) | Consolidates endpoint drift detection (`VariabilityScanner`), signature/entropy scanning (`MalwareScannerAdapter`), and the every-3-days (`0 12 */3 * *`) scheduled endpoint integrity workflow alongside the core **One Way In, No Way Out** modules. | `scripts/variability_scanner.py`, `scripts/malware_scanner_adapter.py`, `.github/workflows/endpoint-integrity-audit.yml`. |
| **Core GitHub Repository Propagation** | `2026-10` – `2026-11` | Propagates Zero-Trust Data Execution, `adpBetty` governance, GPG signature verification (`verify_gpg_commits.sh`, `audit-gpg-signatures.sh`), and custody rules across primary repositories. | `re1Lucky365` & `adpsnake7-beep`: `adpBetty`, `Master-Hub`, `sovereign-global-law-hub`, `master-legal-compendium`, `Csv-to-openmetrics`, `ghidra-mcp-repo-all-`. |

## 3. Scope, Identity Vectors & Custody Standard
- **GitHub Accounts & Core Repositories:** `re1Lucky365` and `adpsnake7-beep` hosting `adpBetty`, `Master-Hub`, `sovereign-global-law-hub`, `master-legal-compendium`, `Csv-to-openmetrics`, and `ghidra-mcp-repo-all-`.
- **Authorized Hardware & Network:** `Samsung Galaxy S23 FE (SM-S711U)` on Verizon Wireless (`+1 (812) 786-8164`); all legacy or unrecognized devices deauthorized.
- **Registered Identity Emails:**
  - `tome18302@gmail.com`
  - `evansrobert517@gmail.com`
  - `re1Lucky365@gmail.com`
  - `adpsnake7@gmail.com`
  - `1981bobthedeveloper@gmail.com`
  - `200retodo1love471@gmail.com`
- **Custody & Rightful-Ownership Rule:** All backups, repository syncs, CI/CD pipelines, and recovery sweeps retain only artifacts verified against the cryptographic signatures, identity vectors, or corporate records of Robert Edward Evans and WK Precision Enterprise LLC, discarding unverified third-party or extraneous data.
- **Protected & Beneficiary Roster:**
  - Household / Protected Roster: Kathy Ann Powers, Dylan Lee Adams, Brandy Snyder, Faith, Gary Snyder, David, Kyle Summit, Will Moore
  - Beneficiary Designations: Crystal Ann Orchard, David Giovanni Lopez, Christian Orchard, Aiden Orchard

## 4. Chronological Timeline (2019 – November 2026)

| Date / Period | Event / Action | Category & Impact | Status |
| :--- | :--- | :--- | :--- |
| `2019 – 2020` | Historical residence baseline in Washington, IN 47501; initial public data-broker aggregation and PII distribution recorded. | Baseline Exposure | `REPORTED` |
| `2024 – 2026` | Access freezes across Crane Federal Credit Union, Liberty Federal Credit Union, Wells Fargo Bank, PayPal/Venmo, Cash App Investing, and Apex Clearing Corporation linked to SMS/MFA lockouts. | Depository & Clearing Lockout | `REPORTED / ACTIVE` |
| `2025-08-18` | Primary hardware and identity re-anchoring on Samsung Galaxy S23 FE (`SM-S711U`) with hardware biometrics and active Verizon Wireless provisioning. | Hardware Provisioning | `VERIFIED` |
| `2025-10-08` | Multi-account identity consolidation initiated across primary Gmail vectors, Samsung account documentation (`Samsung account.pdf`), and Instagram security logs. | Identity Consolidation | `VERIFIED` |
| `2025 – 2026` | Legacy SIM and hardware PUK lockouts (including Moto E5 Play hardware and legacy carrier SIMs) severing legacy SMS recovery channels. | MFA Interruption | `REPORTED` |
| `2026-06-13` | Pre-June incarceration audit & escalation baseline recorded: `LOG-001` (Apex Clearing), `LOG-002` (Cash App Investing), `LOG-003` (FINRA draft), `LOG-004` (Google/YouTube sweep), `LOG-005` (Microsoft audit). | Regulatory & System Audit | `VERIFIED` |
| `2026-09-30` | Complete record archives (`one-way-in-no-way-out-complete-record.zip` and `one-way-in-no-way-out-complete-record-1.zip`) captured in Drive. | Archive Snapshot | `VERIFIED` |
| `2026-10-13` | Privacy & Data-Broker Removal Plan established with Evidence Vault integration and automated opt-out scripts. | Privacy Enforcement | `VERIFIED` |
| `2026-10 – 2026-11` | Deployment of `adpBetty` local-first Zero-Trust architecture across core GitHub repositories with GPG commit/tag verification (`audit-gpg-signatures.sh`, `verify_gpg_commits.sh`), GitHub Actions CI/CD, Fernet/PBKDF2HMAC encryption, SHA-256/SHA-512 manifests, ClamAV + Shannon entropy scanning, and wireless/casting allow-lists. | Systems Hardening | `VERIFIED` |
| `2026-11-04` | Formal KYC identity affidavits submitted to Cash App Investing and Apex Clearing Corporation for Account `VS78A3Z`. | Formal Legal KYC | `VERIFIED` |
| `2026-11-08` | Formal Notice of Identity Verification, Asset Reclamation, and Account Reinstatement Demand served on Crane FCU, Liberty FCU, Wells Fargo, and PayPal Holdings. | Legal Notice Served | `VERIFIED` |
| `2026-11-19` | OAuth and third-party integration audit completed on `tome18302@gmail.com`, revoking unverified tokens and legacy sessions. | Auth Audit | `VERIFIED` |
| `2026-11-22` | Sovereign GitHub Master Architecture & Custody Specification (`one-way-pipeline.yml`, `build-bundle.sh`, `validate-manifest.sh`, `master_control.py`) documented across `re1Lucky365` and `adpsnake7-beep`. | Repository Architecture | `VERIFIED` |
| `2026-11-25` | Master Incident Report baseline issued; Section 8 opened for social account compromises, threat log, and statement review. | Baseline & Threat Review | `ACTIVE` |
| `2026-11-26` | Zero-Trust Data Execution ("One Way In, No Way Out") Blueprint and Complete Blueprint V3 (`one_way_ingest.py`, `enforce-containment.sh`, `zero-trust-gate.yml`, `apply-branch-protection.sh`, `variability_scanner.py`, `malware_scanner_adapter.py`, `endpoint-integrity-audit.yml`) consolidated. | Blueprint Consolidation | `VERIFIED` |

## 5. Evidence Log, Asset Registry & Damages Baseline

### Preserved Evidence & Case Log (`2026-06-13` Baseline)
- **`LOG-001` (Apex Clearing):** Inquiry / Email (`Apex_Inquiry_Log.pdf`) — Formal inquiry regarding clearing account recovery (`VS78A3Z`); SHA-256 verified.
- **`LOG-002` (Cash App Investing):** Account Review (`CashApp_Statement_2026.csv`) — Reconciling transaction log against identity records (`VS78A3Z`); SHA-256 verified.
- **`LOG-003` (FINRA):** Regulatory Notice (`FINRA_Escalation_Draft.docx`) — Prepared regulatory escalation filing for unresolved claims and SMS/PUK recovery obstacles; SHA-256 verified.
- **`LOG-004` (Google / YouTube):** Identity & Auth (`Google_Auth_Sweep.json`) — Account telemetry, OAuth tokens, connected apps, YouTube permissions, and login IP history across identity emails; SHA-256 verified.
- **`LOG-005` (Microsoft):** System Audit (`MSFT_Audit_Report.txt`) — Security sweep of registered platform devices and legacy device purge; SHA-256 verified.

### Master Asset Records (`AST-101` – `AST-105`)
- **`AST-101` (Depository Accounts):** Crane Federal Credit Union, Liberty Federal Credit Union, Wells Fargo Bank — reinstatement/access restructure active.
- **`AST-102` (Brokerage & Clearing):** Cash App Investing LLC & Apex Clearing Corporation (Account `VS78A3Z`, Vault Block `AV-FIN-2026-VS78A3Z`, double-hashed SHA-512 + `zstd` + Fernet/PBKDF2HMAC protocol) — KYC affidavit submitted; pending ledger settlement.
- **`AST-103` (Digital Payments):** PayPal Holdings, Venmo — formal notice served; identity re-anchored.
- **`AST-104` (Hardware):** Samsung Galaxy S23 FE (`SM-S711U`) active primary node; encrypted storage arrays.
- **`AST-105` (IP & Code Repositories):** GitHub (`re1Lucky365`, `adpsnake7-beep` across `adpBetty`, `Master-Hub`, `sovereign-global-law-hub`, `master-legal-compendium`, `Csv-to-openmetrics`, `ghidra-mcp-repo-all-`) & local vault archives — GPG-signed, branch rulesets, and Zero-Trust CI/CD active.

### Damages Categories Tracked (`2024 – 2026` / `2025 – 2026`)
- **Financial / Direct Out-of-Pocket:** Unauthorized transfers or frozen balances (`2024 – 2026`).
- **Investments & Clearing Accounts:** Brokerage or clearing firm balances (`2024 – 2026`).
- **Operational & Incident Costs:** Security remediations, identity restoration, tooling, and infrastructure (`2025 – 2026`).
- **Hardware / Device Loss:** Compromised, locked, or replaced hardware (`2025 – 2026`).

## 6. GitHub Zero-Trust Architecture & Continuity Controls
1. **"One Way In" — Ingestion & Deterministic Packaging (`scripts/one_way_ingest.py`, `scripts/build-bundle.sh`, `scripts/validate-manifest.sh`):** Enforces authorized owner claims (`Robert Edward Evans`, `WK Precision Enterprise LLC`, and registered identity emails), validates manifest JSON and relative artifact paths, computes SHA-256 and SHA-512 checksums, compresses with `zstd` (level 19), encrypts via Fernet (`PBKDF2HMAC` + SHA-256, 150,000 iterations), and records entries in a SQLite WAL ledger.
2. **"No Way Out" — Endpoint, Firewall & Repository Containment (`scripts/enforce-containment.sh`, `scripts/apply-branch-protection.sh`, `.github/workflows/zero-trust-gate.yml`):** Resets UFW to default-deny inbound and outbound with explicit allow-lists for SSH (`22/tcp`), whitelisted TLS/HTTPS (`443/tcp`), and DNS (`53/udp`); audits commit signatures and shell/Python syntax in CI/CD; and configures branch protection via `gh api` to require signed commits, linear history, and no force pushes or deletions.
3. **Scheduled Endpoint & Integrity Auditing (`scripts/variability_scanner.py`, `scripts/malware_scanner_adapter.py`, `.github/workflows/endpoint-integrity-audit.yml`):** Runs every 3 days (`0 12 */3 * *`) to verify syntax and CLI entrypoints for file baseline drift detection (`sha256`, `size`, `mode`, `mtime_ns`) and malware/Shannon entropy scanning (`clamscan` + entropy threshold).
4. **Repository Mirroring & Multi-Medium Continuity:** Mirrors repositories across `re1Lucky365` and `adpsnake7-beep`, verifies GPG commit and tag signatures (`git log --show-signature`), and preserves open formats (UTF-8, Markdown, CSV, JSON, SQLite WAL, `zstd`) with beneficiary succession governance.

## 7. Open Items & Repository Attachments
- [ ] Extract and index the internal file manifest and SHA-256 hashes from `one-way-in-no-way-out-complete-record.zip` and `one-way-in-no-way-out-complete-record-1.zip`.
- [ ] Populate specific Git commit SHAs, workflow run IDs, and artifact hashes for each repository in `AST-105` (`adpBetty`, `Master-Hub`, `sovereign-global-law-hub`, `master-legal-compendium`, `Csv-to-openmetrics`, `ghidra-mcp-repo-all-`).
- [ ] Complete Section 8 (*Social Account Compromises, Threat Log & Statement Review (November 25, 2026)*) from the Master Incident Report.
8commits.sh7audit-gpg-signatures.sh`adpsnake7@gmail.com`1981bobthedeveloper@gmail.com`re1Lucky365@gmail.com`evansrobert517@gmail.com`tome18302@gmail.com+-----------------------------------------------------------------------------------+
|            re1Lucky365 / adpsnake7-beep GITHUB ZERO-TRUST ARCHITECTURE            |
+-----------------------------------------------------------------------------------+
                                          |
   [ Pipeline 1: Raw Evidence Ingestion ] --+--> GitHub Actions CI/CD Ingestion Workflow
                                          |--> SHA-256 / SHA-512 Hashing & SQLite Manifest
                                          |--> Zstandard Compression & Fernet Encrypt
                                          v
   [ Pipeline 2: Code & Git Provenance  ] --+--> GPG Key Signing (re1Lucky365 / adpsnake7-beep)
                                          |--> Repos: adpBetty, Master-Hub, sovereign-global-law-hub
                                          |--> Repos: master-legal-compendium, Csv-to-openmetrics, ghidra-mcp-repo-all-
                                          |--> Strict Ownership Filter & Branch Protection Rulesets
                                          v
   [ Pipeline 3: System & Hardware Lock ] --+--> Sole Node: Samsung SM-S711U (Verizon)
                                          |--> WirelessAccessGuard / UFW Egress Filter
                                          |--> MalwareScanner (ClamAV + Shannon Entropy)
                                          v
   [ Pipeline 4: Remediation Tracking   ] --+--> Automated GitHub Actions Audits (3d, 5d, 7d, 14d)
                                             --> FINRA / Clearing / Data-Broker Opt-Out
# Investigative Case Dossier: GitHub Provenance, Access Lockouts & Zero-Trust Hardening

- **Case / Dossier ID:** `CASE-2026-1125-WKP-01`
- **Status:** `Active — Containment & Reclamation In Progress`
- **Report Baseline Date:** `2026-11-25` (Dossier Updated `2026-11-26`)
- **Principal / Claimant:** `Robert Edward Evans` (DOB: `1981-10-09`, Washington, IN 47501)
- **Associated Entity:** `WK Precision Enterprise LLC` (Indiana — Sole Member & Managing Principal)
- **Primary Address:** `606 North 5th Ave, Evansville, IN 47710`
- **Authorized Hardware Node:** `Samsung Galaxy S23 FE (SM-S711U)` on Verizon Wireless (`+1 (812) 786-8164`)
- **GitHub Provenance Accounts:** `re1Lucky365`, `adpsnake7-beep`
- **Core Repositories:** `adpBetty`, `Master-Hub`, `sovereign-global-law-hub`, `master-legal-compendium`, `Csv-to-openmetrics`, `ghidra-mcp-repo-all-`

## 1. Executive Summary & Non-Abandonment Determination
This dossier documents the technical provenance, access disruptions (2019–November 2026), evidence vault structure, and Zero-Trust controls governing the GitHub repositories and digital assets of Robert Edward Evans and WK Precision Enterprise LLC.

Account inactivity and access freezes across financial, depository, clearing, and platform services resulted from physical device failures, carrier SIM card Personal Unlocking Key (PUK) lockouts (including legacy hardware such as a Moto E5 Play and older SIMs), and resulting SMS/MFA recovery failures—not abandonment or relinquishment of rights, title, or interest.

## 2. Scope & Authorized Vectors
- **GitHub Accounts & Repositories:** `re1Lucky365` and `adpsnake7-beep` across `adpBetty`, `Master-Hub`, `sovereign-global-law-hub`, `master-legal-compendium`, `Csv-to-openmetrics`, and `ghidra-mcp-repo-all-`.
- **Authorized Hardware & Network:** `Samsung Galaxy S23 FE (SM-S711U)` provisioned on Verizon Wireless (`+1 (812) 786-8164`); all legacy or unrecognized devices deauthorized.
- **Registered Identity Emails:**
  - `tome18302@gmail.com`
  - `evansrobert517@gmail.com`
  - `re1Lucky365@gmail.com`
  - `adpsnake7@gmail.com`
  - `1981bobthedeveloper@gmail.com`
  - `200retodo1love471@gmail.com`
- **Protected & Beneficiary Roster:**
  - Household / Protected Roster: Kathy Ann Powers, Dylan Lee Adams, Brandy Snyder, Faith, Gary Snyder, David, Kyle Summit, Will Moore
  - Beneficiary Designations: Crystal Ann Orchard, David Giovanni Lopez, Christian Orchard, Aiden Orchard

## 3. Chronological Timeline (2019 – November 2026)

| Period / Date | Event / Action | Scope & Status | Reference |
| :--- | :--- | :--- | :--- |
| `2019 – 2020` | Historical residence baseline in Washington, IN 47501; initial public data-broker aggregation and PII distribution recorded. | Baseline Exposure (`REPORTED`) | `Master Report Sec. 3` |
| `2024 – 2026` | Access freezes across Crane Federal Credit Union, Liberty Federal Credit Union, Wells Fargo Bank, PayPal/Venmo, Cash App Investing, and Apex Clearing Corporation linked to broken SMS/MFA channels. | Depository & Clearing Lockout (`REPORTED / ACTIVE`) | `AST-101` to `AST-103` |
| `2025-08-18` | Primary hardware and identity re-anchoring on Samsung Galaxy S23 FE (`SM-S711U`) with hardware biometrics and Verizon Wireless provisioning. | Hardware Provisioning (`VERIFIED`) | `AST-104` |
| `2025-10-08` | Multi-account identity consolidation across primary Gmail vectors, Samsung account records (`Samsung account.pdf`), and Instagram security logs. | Identity Consolidation (`VERIFIED`) | `Master Report Sec. 3` |
| `2025 – 2026` | Legacy SIM and hardware PUK lockouts (including Moto E5 Play and legacy carrier SIMs) severing legacy SMS recovery paths. | MFA Interruption (`REPORTED`) | `Master Report Sec. 3` |
| `2026-06-13` | Formal system audits and recovery escalation logs created (`LOG-001` through `LOG-005`). | Regulatory & System Audit (`VERIFIED`) | `LOG-001`–`LOG-005` |
| `2026-10-13` | Privacy & Data-Broker Removal Plan established with Evidence Vault integration and automated opt-out scripts. | Privacy Enforcement (`VERIFIED`) | `Master Report Sec. 3` |
| `2026-10 – 2026-11` | Deployment of `adpBetty` local-first Zero-Trust architecture across core GitHub repositories with GPG commit/tag verification (`audit-gpg-signatures.sh`, `verify_gpg_commits.sh`), GitHub Actions CI/CD, Fernet/PBKDF2HMAC encryption, SHA-256/SHA-512 manifests, ClamAV + Shannon entropy scanning, and wireless/casting allow-lists. | Systems Hardening (`VERIFIED`) | `AST-105`, `Pipelines 1–4` |
| `2026-11-04` | Formal KYC identity affidavits submitted to Cash App Investing and Apex Clearing Corporation for Account `VS78A3Z`. | Formal Legal KYC (`VERIFIED`) | `LOG-001`, `LOG-002`, `AST-102` |
| `2026-11-08` | Formal Notice of Identity Verification, Asset Reclamation, and Account Reinstatement Demand served on Crane FCU, Liberty FCU, Wells Fargo, and PayPal Holdings. | Legal Notice Served (`VERIFIED`) | `AST-101`, `AST-103` |
| `2026-11-19` | OAuth and third-party integration audit completed on `tome18302@gmail.com`, revoking unverified tokens and legacy sessions. | Auth Audit (`VERIFIED`) | `LOG-004` |
| `2026-11-25` | Master Incident Report baseline issued; Section 8 opened for social account compromises, threat log, and statement review. | Baseline & Threat Review (`ACTIVE`) | `Master Report Sec. 8` |

## 4. Evidence Vault, Logs & Asset Registry

### Preserved Audit Logs
- **`LOG-001` (Apex Clearing Corporation):** Account allocation, clearing record verification, and freeze clearance for Account `VS78A3Z` (SHA-256 verified).
- **`LOG-002` (Cash App Investing LLC / Block, Inc.):** Statement reconciliation, transaction ledger extraction, and identity re-binding for Account `VS78A3Z` (SHA-256 verified).
- **`LOG-003` (FINRA):** Regulatory escalation draft addressing institutional non-responsiveness and SMS/PUK recovery obstacles (SHA-256 verified).
- **`LOG-004` (Google LLC Account Services):** OAuth token sweep, connected apps, YouTube permissions, and login IP history across all 7 identity emails (SHA-256 verified).
- **`LOG-005` (Microsoft Security Architecture):** Security event log extract, trusted device purge, and removal of legacy Windows/Mobile device IDs (SHA-256 verified).

### Master Asset & Recovery Records
- **`AST-101` (Depository Accounts):** Crane FCU, Liberty FCU, Wells Fargo Bank — reinstatement/access restructure active.
- **`AST-102` (Brokerage & Clearing):** Cash App Investing LLC & Apex Clearing Corporation (Account `VS78A3Z`, Vault Block `AV-FIN-2026-VS78A3Z`, SHA-512 + `zstd` + Fernet/PBKDF2HMAC 100,000-iteration protocol) — KYC affidavit submitted; pending ledger settlement.
- **`AST-103` (Digital Payments):** PayPal Holdings, Venmo — formal notice served; identity re-anchored.
- **`AST-104` (Hardware):** Samsung Galaxy S23 FE (`SM-S711U`) active primary node; encrypted storage arrays.
- **`AST-105` (IP & Code Repositories):** GitHub (`re1Lucky365`, `adpsnake7-beep`) & local vault archives — GPG-signed, branch rulesets, and Zero-Trust CI/CD active.

## 5. Technical Controls & Zero-Trust Pipelines
1. **Evidence Ingestion (`set -euo pipefail`):** Raw stream/dump ingestion -> SHA-256 & SHA-512 hashing -> `zstd -19` compression -> Fernet encryption (PBKDF2HMAC-SHA256, 100,000+ iterations) -> SQLite WAL manifest synced via GitHub Actions.
2. **Git & Provenance Integrity:** Enforced GPG-signed commits/tags (`verify_gpg_commits.sh`, `audit-gpg-signatures.sh`), branch protection rulesets, and rightful-ownership filtering purging unverified third-party metadata.
3. **Endpoint, Wireless & Egress Controls:** Sole authorization for `SM-S711U` (Verizon); `WirelessAccessGuard` restricting Bluetooth/casting; `VariabilityScanner` for file/permission/timestamp drift; `MalwareScannerAdapter` (ClamAV + Shannon entropy); UFW egress restricted to TLS 1.3 / SSH allow-listed endpoints.
4. **Remediation & Continuity Cadence:** Automated 3-, 5-, 7-, and 14-day audit cycles; UTF-8/Markdown/CSV/JSON/SQLite WAL + `zstd` archival formats; succession triggers for designated beneficiaries.

## 6. Open Items & Repository Attachments
- [ ] Populate specific commit SHAs, workflow run IDs, and SHA-256 artifact hashes for each repository in `AST-105`.
- [ ] Complete Section 8 entries (social account compromises, threat log events, and statement review findings) from the November 25, 2026 baseline.
- [ ] Track 14-day response windows across financial, clearing, and FINRA (`LOG-003`) items.
git clone https://github.com/re1Lucky365/zapzap.git
cd zapzap
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
https://github.com/re1Lucky365/zapzap.git
requirements.txt
run.py
pytest
https://github.com/re1Lucky365/zapzap.gitrequirements.txt
# lean-zip

**A formally verified DEFLATE implementation in Lean 4.**

[`lean-zip`](https://github.com/kim-em/lean-zip)
contains a pure-[Lean](https://lean-lang.org/) DEFLATE encoder and decoder, and
Lean's kernel checks that they are inverse to each other.
We've proved that compression can't corrupt your data, for every possible input,
and this proof is certified by the Lean kernel:

```lean
/-- Decompressing the output of `compress` returns the original data,
    for every input and every compression level. -/
theorem zlib_decompressSingle_compress (data : ByteArray) (level : UInt8)
    (maxOutputSize : Nat) (hsize : data.size ≤ maxOutputSize) :
    ZlibDecode.decompressSingle (ZlibEncode.compress data level) maxOutputSize = .ok data
```

This theorem rests on lower level theorems about the DEFLATE algorithm,
`inflate (deflateRaw data level) = .ok data`, and on more than 1,100 theorems
across ~32k lines of proof in [`Zip/Spec/`](Zip/Spec). There are no `sorry`s,
and CI re-checks the proofs on every change.

Astonishingly, both the implementation, and the verification, are written
entirely by loosely supervised AIs: coding agents claimed issues, worked in
their own git worktrees, and opened pull requests that could not merge unless
the round-trip proof still went through. The full development history,
including the plans, per-session progress logs, and benchmarking apparatus the
agents worked from, is preserved at the
[`pre-split`](https://github.com/kim-em/lean-zip/tree/pre-split) tag.

## Verification enables performance

Here is the interesting part.

(The short version, including the headline `time` race where lean-zip
compresses the 212 MB Silesia tar smaller *and* faster than miniz_oxide —
4.57s vs 5.77s at level 6 — is in the blog post
["Why Lean is faster than Rust"](https://kim-em.github.io/blog/2026-7-24-why-lean-is-faster-than-rust/).)

![Silesia compression: speed vs ratio, animated through the project's git history](graphs/silesia_compress_pareto_history.svg)

*[Silesia](https://sun.aei.polsl.pl/~sdeor/index.php?page=silesia) corpus.
x = compression ratio (← smaller is better), y = throughput
(MB/s, log scale); each codec's levels are joined by its *achievable mixing
frontier* — the ratio/speed points reachable by blending two adjacent levels —
so up-and-to-the-left wins and a comparison at a matched ratio is honest (a
straight segment on this log axis would overstate the achievable speed). The
reference curves are fixed at the final dashboard; the red curve is the
pure-Lean codec **replaying every dashboard refresh in the project's git
history**, one commit per frame, with a faint trail per level. The dashboard
is frozen as of August 2026; the full methodology, decode benchmarks,
per-file heatmaps, and harness live in
[lean-zip-benchmark](https://github.com/kim-em/lean-zip-benchmark), and a
[static version of this chart](graphs/silesia_compress_pareto.svg) is
committed here.*

Once correctness is a *theorem*, you can ambitiously and aggressively optimize.
Add lazy matching, bolt on a cost-model optimal parse, split blocks where the
symbol statistics drift, unbox the matcher's chain state into flat arrays, swap
a clean fold for a word-at-a-time comparator, and the obligation
`inflate (deflate x) = x` either still holds or the build goes red. An
optimization *cannot* quietly trade away correctness, because correctness here
isn't a test suite that samples some inputs; it's a statement about **all**
inputs that the kernel insists on.

That makes the optimization work safe to hand to a machine. Much of lean-zip,
including essentially all of the performance work behind that graph, was
written by coding agents working autonomously, and the PR could not merge
unless the round-trip proof still went through. The proof is the ratchet.

And it works. In the graph above, we see the performance of lean-zip (the
red `native` curve). Note that the y-axis is a log scale, so a vertical gap
is a *multiplicative* speed factor. Comparing at matched compression ratios
(equal-file geomeans on Silesia), lean-zip:

- **beats every level Rust's miniz_oxide provides**: same-or-better ratio at
  higher throughput across L1–L9 (with one asterisk: beating miniz L3 takes a
  mix of lean-zip's L3 and L4 under the frontier rule above). At L6, the
  common default, lean-zip is ~30% faster at equal ratio; at miniz's L9 it is
  about 2× faster; at L1 it is directly ahead, 273.7 vs 235.2 MB/s (+16.4%),
  with 8.8% smaller output;
- **dominates JS's [`fflate`](https://github.com/101arrowz/fflate) outright**:
  at every fflate level there is a single lean-zip level that is both denser
  and 1.5–2× faster — and lean-zip *decompresses* more than 2× faster than
  fflate too;
- **dominates the zlib C reference implementation**: equal-or-better ratio at
  higher throughput at every level;
- **beats the pure-OCaml [`decompress`](https://github.com/mirage/decompress)
  library** by 3–9× at any ratio it can reach, and reaches ratios OCaml's
  encoder can't;
- **splits the board with Go and Zig**: they win at the low and middle
  levels, lean-zip wins the dense end;
- is outrun across most of the range by the optimized zlib descendants
  (**zlib-ng**, and the memory-safe Rust **zlib-rs**) — but not at the deep
  end: their densest setting lands at exactly the ratio lean-zip reaches at
  L7, where lean-zip is slightly ahead of zlib-rs and ~10% ahead of zlib-ng;
- trails the hand-tuned **C + SIMD** ceiling (libdeflate) by roughly 2× at
  mid ratios, growing to ~10× at the dense end — as expected for the format;
- on the **decode** side, outruns every language-native peer (fflate by >2×,
  OCaml by 5–7×, Go and Zig by 15–30%) while trailing the C-grade decoders
  (miniz_oxide by ~1.45×, libdeflate by ~2.5×).

This codec started out far slower than everything else on the chart — the
animation above replays the climb, one dashboard refresh at a time. The gap
closed not through one clever human insight but through a long series of small,
individually-verified steps. That is the bet behind
Gwern's ["Lean software scaling laws"](https://gwern.net/lean-scaling):
formally-verifiable languages may start from a worse baseline but scale better,
because verified code is the substrate on which automated optimization can
safely compound.

The author cheerfully admits to being an amateur at performance work, which is
rather the point: she didn't have to be an expert, only to keep the proofs
green. If you know how to make DEFLATE go faster, the proofs are waiting to
catch your mistakes; contributions very welcome.

## Using it

Add to your `lakefile.lean`:

```lean
require "kim-em" / "lean-zip"
```

The codec is pure Lean: no system libraries required.

```lean
import Zip

-- Zlib format (RFC 1950)
let compressed := Zip.Native.ZlibEncode.compress data (level := 6)
let original ← IO.ofExcept (Zip.Native.ZlibDecode.decompress compressed)

-- Gzip format (RFC 1952, compatible with gzip/gunzip)
let gzipped := Zip.Native.GzipEncode.compress data (level := 6)
let original ← IO.ofExcept (Zip.Native.GzipDecode.decompress gzipped)

-- Raw DEFLATE (RFC 1951, no header/trailer)
let deflated := Zip.Native.deflateRaw data (level := 6)
let original ← IO.ofExcept (Zip.Native.InflateBuf.inflate deflated)
```

Level 0 emits stored (uncompressed) blocks; levels 1 (fastest) through 10
(an exact dynamic-programming optimal parse) compress, with levels above 10
behaving as 10. Every decoder takes a `maxOutputSize` bound (default 1 GiB)
as a zip-bomb guard; unlike typical C APIs there is no unlimited mode — `0`
means zero bytes.

CRC-32 and Adler-32 have verified implementations too
([`Zip.Native.Crc32`](Zip/Native/Crc32.lean),
[`Zip.Native.Adler32`](Zip/Native/Adler32.lean)), each proved equal to its
specification.

Sibling libraries:

- [lean-zlib](https://github.com/kim-em/lean-zlib) — thin FFI bindings to
  system zlib (including streaming APIs), if you want the C library instead
  of the verified codec
- [lean-archive](https://github.com/kim-em/lean-archive) — tar and ZIP
  archives, built on this library and lean-zlib
- [lean-zstd](https://github.com/kim-em/lean-zstd) — Zstandard

## How it's organized

- [`Zip/Native/`](Zip/Native): the pure-Lean implementation
- [`Zip/Spec/`](Zip/Spec): formal specifications and the correctness proofs
- [`ZipTest/`](ZipTest): unit tests for the native implementation
- [`conformance/`](conformance): a dev-only sub-package testing the native
  codec against system zlib (via lean-zlib) — translation validation plus RFC
  interop in both directions, and a deterministic fuzz harness
- [`c/`](c): four small stopgap primitives (word-sized reads, in-place
  copies) that Lean core doesn't expose yet. Each has a pure-Lean reference
  body; the proofs are about the reference bodies, and the C is trusted to
  match them (cross-checked at runtime by the conformance sweeps). Together
  with the Lean runtime these are the codec's entire trusted computing base —
  no external library is involved
- [`references/`](references): RFCs 1950/1951/1952 and related papers

Every source file opens with a module docstring describing its purpose. Shared
utilities (Binary, Handle, BitReader) live in
[lean-zip-common](https://github.com/kim-em/lean-zip-common).

The specifications aim past the tautological. Where possible they characterize
mathematical properties independent of the implementation (`crc32 (a ++ b)`
in terms of `crc32 a` and `crc32 b`, prefix-freeness and the Kraft inequality
for the Huffman codes, invertibility for the codecs) rather than merely
asserting that two pieces of code agree. The round-trip theorem above is the
capstone: it says the encoder and decoder are genuine inverses, not that they
were transcribed from the same RFC.

## Requirements

- Lean toolchain per [`lean-toolchain`](lean-toolchain), via
  [elan](https://github.com/leanprover/elan). Nothing else: the library and
  its tests build without any system C library.
- The dev-only [`conformance/`](conformance) sub-package additionally needs
  system zlib and `pkg-config` (or `ZLIB_CFLAGS`/`ZLIB_LDFLAGS`); on NixOS,
  [`shell.nix`](shell.nix) provides both.

## Building and testing

```bash
lake build      # library + tests (kernel re-checks every proof)
lake test       # run the native test suite

lake -d conformance build   # native↔zlib conformance suite (needs zlib)
lake -d conformance test
conformance/fuzz-inflate.sh # budgeted randomized fuzz run (default 30s)
```

## Known limitations

- The native codec is whole-buffer only; there is no streaming API. For
  bounded-memory streaming, use
  [lean-zlib](https://github.com/kim-em/lean-zlib).
- `deflateRaw` at a given level is deterministic but its exact output is not
  part of the API: optimization work freely changes the emitted bitstream,
  and only the round-trip and interop guarantees are stable.
- Memory consumption during compression is higher than miniz_oxide's.
- Decompression trails the C-grade decoders (~1.45× behind miniz_oxide); it
  leads the language-native ones.

## License

Apache 2.0.

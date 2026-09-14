#!/usr/bin/env bash
set -uo pipefail

# Installs the open-source command-line tools behind Hanzo/HexStrike adapters.
# Run this inside the dedicated Kali VM, never on the Windows/IIS target.

PROFILE="--core"
DRY_RUN=0
for argument in "$@"; do
  case "$argument" in
    --core|--full) PROFILE="$argument" ;;
    --dry-run) DRY_RUN=1 ;;
    *) echo "Usage: $0 [--core|--full] [--dry-run]" >&2; exit 2 ;;
  esac
done
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This installer is for the Hanzo Kali/Linux worker." >&2
  exit 1
fi
for dependency in apt-get dpkg-query; do
  command -v "$dependency" >/dev/null 2>&1 || { echo "$dependency is required (use Kali/Debian)." >&2; exit 1; }
done
PRIVILEGE=()
if (( EUID != 0 )); then
  command -v sudo >/dev/null 2>&1 || { echo "sudo is required when not running as root." >&2; exit 1; }
  PRIVILEGE=(sudo)
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPORT_DIR="${PROJECT_DIR}/.hanzo-data"

core_packages=(
  nmap masscan rustscan gobuster dirb nikto sqlmap hydra john hashcat
  ffuf feroxbuster dirsearch nuclei wpscan whatweb wafw00f amass subfinder
  fierce dnsenum theharvester enum4linux enum4linux-ng smbmap netexec
  responder smbclient nbtscan arp-scan medusa patator hashid
  gdb radare2 binwalk checksec ropper foremost steghide libimage-exiftool-perl
  testdisk scalpel sleuthkit wireshark tshark tcpdump curl httpie
)
full_packages=(
  aircrack-ng kismet autopsy volatility3 hashcat-utils ophcrack
  metasploit-framework exploitdb wfuzz xsser dotdotpwn commix
  trivy kube-hunter kube-bench prowler checkov
)

packages=("${core_packages[@]}")
if [[ "$PROFILE" == "--full" ]]; then
  packages+=("${full_packages[@]}")
fi
if (( DRY_RUN )); then
  printf 'Package plan (no changes):\n'
  printf '%s\n' "${packages[@]}"
  exit 0
fi
mkdir -p "$REPORT_DIR" || exit 1
RUN_DIR="$(mktemp -d "$REPORT_DIR/arsenal-install.XXXXXX")" || exit 1
REPORT_FILE="$RUN_DIR/report.txt"
printf 'HANZO Kali arsenal installation %s\n' "$PROFILE" > "$REPORT_FILE"
echo "Refreshing Kali package metadata..."
if ! "${PRIVILEGE[@]}" apt-get update > "$RUN_DIR/apt-update.log" 2>&1; then
  printf 'FAILED  apt-get update; no packages installed. See %s\n' "$RUN_DIR/apt-update.log" | tee -a "$REPORT_FILE"
  exit 1
fi

failed=0
install_one() {
  local package="$1"
  if [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null)" == "install ok installed" ]]; then
    printf 'READY  %s\n' "$package" | tee -a "$REPORT_FILE"
    return
  fi
  if "${PRIVILEGE[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" > "$RUN_DIR/$package.log" 2>&1; then
    if [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null)" == "install ok installed" ]]; then
      printf 'INSTALLED  %s\n' "$package" | tee -a "$REPORT_FILE"
    else
      printf 'FAILED VERIFICATION  %s (see %s)\n' "$package" "$RUN_DIR/$package.log" | tee -a "$REPORT_FILE"
      failed=$((failed + 1))
    fi
  else
    printf 'FAILED  %s (see %s)\n' "$package" "$RUN_DIR/$package.log" | tee -a "$REPORT_FILE"
    failed=$((failed + 1))
  fi
}

for package in "${packages[@]}"; do install_one "$package"; done

printf '\n%s\n' \
  'MANUAL / SERVICE-BASED ADAPTERS' \
  '- Burp Suite MCP: install Burp Suite and the MCP Server extension.' \
  '- PentAGI, Shannon, Decepticon: follow their supported runtime/service instructions.' \
  '- Cloud tools: credentials and target subscriptions are separate from binary installation.' \
  '- Commercial GUI tools are not auto-installed.' \
  '- Package installation does not prove a scanner can execute or a service is online.' | tee -a "$REPORT_FILE"

echo
echo "Report: $REPORT_FILE"
echo "Start Hanzo and open Security tools; it will verify every executable via PATH."
if (( failed > 0 )); then
  echo "$failed packages failed installation or verification; see their retained logs."
  exit 1
fi
echo "All requested packages are installed. Check executable and service readiness in HANZO."

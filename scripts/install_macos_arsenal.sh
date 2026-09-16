#!/usr/bin/env bash
set -uo pipefail

# Installs the open-source command-line tools behind Hanzo/HexStrike adapters on macOS.
# Kali remains the intended worker; this makes the development Mac genuinely usable.
# Every install is verified on PATH afterwards. Nothing is reported as ready unless the
# executable is actually found.

PROFILE="--core"
DRY_RUN=0
for argument in "$@"; do
  case "$argument" in
    --core|--full) PROFILE="$argument" ;;
    --dry-run) DRY_RUN=1 ;;
    *) echo "Usage: $0 [--core|--full] [--dry-run]" >&2; exit 2 ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer is for macOS. On Kali use scripts/install_kali_arsenal.sh." >&2
  exit 1
fi
command -v brew >/dev/null 2>&1 || {
  echo "Homebrew is required: https://brew.sh" >&2; exit 1; }

# Several adapters have no wheels for the newest Python. Prefer the interpreter
# the project itself targets, and fall back only if it is absent.
TOOL_PYTHON="$(command -v python3.11 || command -v python3.12 || command -v python3)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPORT_DIR="${PROJECT_DIR}/.hanzo-data"
BIN_DIR="${PROJECT_DIR}/tools/bin"
TOOLS_VENVS="${PROJECT_DIR}/tools/pyenvs"

# Keep download and build caches on the volume the project lives on. Homebrew,
# Go and pip otherwise fill the boot disk, which is what breaks these installs.
CACHE_DIR="${PROJECT_DIR}/.cache"
mkdir -p "$CACHE_DIR/homebrew" "$CACHE_DIR/go/pkg/mod" "$CACHE_DIR/go/build" "$CACHE_DIR/pip"
export HOMEBREW_CACHE="$CACHE_DIR/homebrew"
export GOPATH="$CACHE_DIR/go"
export GOMODCACHE="$CACHE_DIR/go/pkg/mod"
export GOCACHE="$CACHE_DIR/go/build"
export PIP_CACHE_DIR="$CACHE_DIR/pip"

available_mb() { df -m "$1" 2>/dev/null | awk 'NR==2 {print $4}'; }
BOOT_FREE_MB="$(available_mb /System/Volumes/Data)"
if [[ -n "$BOOT_FREE_MB" && "$BOOT_FREE_MB" -lt 3000 ]]; then
  echo "Warning: only ${BOOT_FREE_MB} MB free on the boot volume." >&2
  echo "Homebrew installs into /opt/homebrew on that volume regardless of HOMEBREW_CACHE." >&2
  echo "Free space first (brew cleanup --prune=all, go clean -modcache) or installs will fail." >&2
fi

# Prebuilt macOS binaries, installed into tools/bin. Preferred over Homebrew:
# they need no compiler, and on a project volume they never touch the boot disk.
ARCH="$(uname -m)"
release_binaries=(
  "epi052/feroxbuster|aarch64-macos-feroxbuster.tar.gz|feroxbuster"
  "hahwul/dalfox|*macos-aarch64.tar.gz|dalfox"
  "lc/gau|*darwin_arm64.tar.gz|gau"
  "aquasecurity/trivy|*macOS-ARM64.tar.gz|trivy"
  "aquasecurity/kube-bench|*darwin_arm64.tar.gz|kube-bench"
  "tenable/terrascan|*Darwin_arm64.tar.gz|terrascan"
  "jaeles-project/jaeles|*macos-arm64.zip|jaeles"
)
if [[ "$ARCH" != "arm64" ]]; then
  release_binaries=(
    "epi052/feroxbuster|x86_64-macos-feroxbuster.tar.gz|feroxbuster"
    "hahwul/dalfox|*macos-x86_64.tar.gz|dalfox"
    "lc/gau|*darwin_amd64.tar.gz|gau"
    "aquasecurity/trivy|*macOS-64bit.tar.gz|trivy"
    "aquasecurity/kube-bench|*darwin_amd64.tar.gz|kube-bench"
    "tenable/terrascan|*Darwin_x86_64.tar.gz|terrascan"
    "jaeles-project/jaeles|*macos-amd64.zip|jaeles"
  )
fi

# Homebrew formulas that back a bundled adapter. On macOS 13 and older Homebrew
# is a Tier 3 configuration and compiles these from source, so the heavyweight
# ones are kept out of --core deliberately.
brew_core=(
  nmap masscan rustscan arp-scan
  nikto amass fierce arjun
)
# Kept here only where no prebuilt binary or pip package exists. On macOS 13
# these compile from source, so they are deliberately outside --core.
brew_full=(
  hydra john-jumbo hashcat
  gdb radare2 exiftool foremost
)

# Go adapters with no Homebrew formula. Installed into tools/bin.
go_core=(
  "github.com/tomnomnom/waybackurls@latest|waybackurls"
  "github.com/tomnomnom/anew@latest|anew"
  "github.com/tomnomnom/qsreplace@latest|qsreplace"
  "github.com/hakluke/hakrawler@latest|hakrawler"
)
# Go builds write to GOMODCACHE/GOCACHE, both redirected to the project volume.
go_full=("github.com/jaeles-project/jaeles@latest|jaeles")

# Python adapters, each in its own venv. prowler, scoutsuite and pacu pin
# conflicting boto3 versions, so a single shared venv cannot hold them all.
# Entries are package|command.
pip_core=(
  "wafw00f|wafw00f"
  "dirsearch|dirsearch"
  "uro|uro"
)
pip_full=(
  "smbmap|smbmap"
  "ROPgadget|ROPgadget"
  "volatility3|vol"
  "binwalk|binwalk"
  "checkov|checkov"
  "prowler|prowler"
  "scoutsuite|scout"
  "pacu|pacu"
  "kube-hunter|kube-hunter"
)

# Adapters that are genuinely not installable this way on macOS.
unavailable=(
  "metasploit (msfconsole/msfvenom) - use the official macOS installer or a Kali VM"
  "zap (zap.sh) - install the OWASP ZAP desktop app: brew install --cask zap"
  "burpsuite - install Burp Suite and its MCP Server extension manually"
  "netexec / enum4linux / enum4linux-ng / responder / nbtscan / rpcclient - Linux-oriented SMB/AD tooling; use the Kali worker"
  "dirb / dotdotpwn / xsser / wpscan / steghide - no maintained macOS formula; use the Kali worker"
  "netexec - not published to PyPI under that name; install from its repository or use the Kali worker"
  "wfuzz - needs pycurl, which needs libcurl headers to build on macOS; use the Kali worker"
  "ropper - its filebytes dependency fails to build on current Python; use the Kali worker"
  "ghidra (analyzeHeadless) - brew install --cask ghidra, then set its path"
  "scout-suite / pacu / kube-hunter / clair / falco / docker-bench-security - service or cloud tooling with their own setup"
  "angr / pwntools / one_gadget / libc-database / gdb-peda / pwninit - exploit-dev extras with their own runtimes"
)

brew_packages=("${brew_core[@]}")
go_packages=("${go_core[@]}")
pip_packages=("${pip_core[@]}")
if [[ "$PROFILE" == "--full" ]]; then
  brew_packages+=("${brew_full[@]}")
  go_packages+=("${go_full[@]}")
  pip_packages+=("${pip_full[@]}")
fi

if (( DRY_RUN )); then
  printf 'Prebuilt binary plan (no changes):\n'; printf '  %s\n' "${release_binaries[@]##*|}"
  printf 'Homebrew plan:\n'; printf '  %s\n' "${brew_packages[@]}"
  printf 'Go plan:\n'; printf '  %s\n' "${go_packages[@]%%|*}"
  printf 'Python plan:\n'; printf '  %s\n' "${pip_packages[@]%%|*}"
  printf 'Not installable on macOS:\n'; printf '  %s\n' "${unavailable[@]}"
  exit 0
fi

mkdir -p "$REPORT_DIR" "$BIN_DIR" "$TOOLS_VENVS" || exit 1
RUN_DIR="$(mktemp -d "$REPORT_DIR/macos-arsenal.XXXXXX")" || exit 1
REPORT_FILE="$RUN_DIR/report.txt"
printf 'HANZO macOS arsenal installation %s\n\n' "$PROFILE" > "$REPORT_FILE"

failed=0
MIN_FREE_MB=1200

boot_space_ok() {
  local free; free="$(available_mb /System/Volumes/Data)"
  [[ -z "$free" ]] && return 0
  if (( free < MIN_FREE_MB )); then
    printf 'STOPPED  boot volume down to %s MB free (floor %s MB); skipping the rest.\n' \
      "$free" "$MIN_FREE_MB" | tee -a "$REPORT_FILE"
    return 1
  fi
  return 0
}

verify() {
  # Report readiness from PATH, never from the installer's own exit code alone.
  local binary="$1" label="$2"
  if command -v "$binary" >/dev/null 2>&1 || [[ -x "$BIN_DIR/$binary" ]]; then
    printf 'READY  %s (%s)\n' "$label" "$binary" | tee -a "$REPORT_FILE"
  else
    printf 'NOT ON PATH  %s (expected %s)\n' "$label" "$binary" | tee -a "$REPORT_FILE"
    failed=$((failed + 1))
  fi
}

echo "== Prebuilt release binaries into tools/bin =="
if command -v gh >/dev/null 2>&1; then
  for entry in "${release_binaries[@]}"; do
    repo="${entry%%|*}"; rest="${entry#*|}"
    pattern="${rest%%|*}"; binary="${rest##*|}"
    if [[ -x "$BIN_DIR/$binary" ]]; then
      printf 'ALREADY INSTALLED  %s\n' "$binary" | tee -a "$REPORT_FILE"
      verify "$binary" "$binary"
      continue
    fi
    stage="$CACHE_DIR/release/$binary"
    rm -rf "$stage"; mkdir -p "$stage"
    if gh release download --repo "$repo" --pattern "$pattern" --dir "$stage" --clobber \
         > "$RUN_DIR/release-$binary.log" 2>&1; then
      archive="$(find "$stage" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.tgz' -o -name '*.zip' \) | head -1)"
      if [[ -n "$archive" ]]; then
        case "$archive" in
          *.zip) unzip -joq "$archive" -d "$stage" >> "$RUN_DIR/release-$binary.log" 2>&1 ;;
          *) tar -xzf "$archive" -C "$stage" >> "$RUN_DIR/release-$binary.log" 2>&1 ;;
        esac
        extracted="$(find "$stage" -type f -name "$binary" -perm -u+x | head -1)"
        [[ -z "$extracted" ]] && extracted="$(find "$stage" -type f -name "$binary" | head -1)"
        if [[ -n "$extracted" ]]; then
          mv "$extracted" "$BIN_DIR/$binary"
          chmod +x "$BIN_DIR/$binary"
          xattr -d com.apple.quarantine "$BIN_DIR/$binary" 2>/dev/null || true
          printf 'INSTALLED  %s (prebuilt)\n' "$binary" | tee -a "$REPORT_FILE"
        else
          printf 'FAILED  %s: %s not found in the archive (see %s)\n' \
            "$binary" "$binary" "$RUN_DIR/release-$binary.log" | tee -a "$REPORT_FILE"
          failed=$((failed + 1))
        fi
      else
        printf 'FAILED  %s: no archive downloaded (see %s)\n' "$binary" "$RUN_DIR/release-$binary.log" | tee -a "$REPORT_FILE"
        failed=$((failed + 1))
      fi
    else
      printf 'FAILED  %s download (see %s)\n' "$binary" "$RUN_DIR/release-$binary.log" | tee -a "$REPORT_FILE"
      failed=$((failed + 1))
    fi
    rm -rf "$stage"
    verify "$binary" "$binary"
  done
else
  printf 'SKIPPED  prebuilt binaries: the gh CLI is not installed (brew install gh)\n' | tee -a "$REPORT_FILE"
fi

echo
echo "== Homebrew formulas =="
for package in "${brew_packages[@]}"; do
  boot_space_ok || break
  binary="$package"
  case "$package" in
    john-jumbo) binary="john" ;;
    exiftool) binary="exiftool" ;;
  esac
  if brew list --formula "$package" >/dev/null 2>&1; then
    printf 'ALREADY INSTALLED  %s\n' "$package" | tee -a "$REPORT_FILE"
  elif brew install "$package" > "$RUN_DIR/brew-$package.log" 2>&1; then
    printf 'INSTALLED  %s\n' "$package" | tee -a "$REPORT_FILE"
  else
    printf 'FAILED  %s (see %s)\n' "$package" "$RUN_DIR/brew-$package.log" | tee -a "$REPORT_FILE"
    failed=$((failed + 1))
    continue
  fi
  verify "$binary" "$package"
done

echo
echo "== Go adapters into tools/bin =="
if command -v go >/dev/null 2>&1; then
  for entry in "${go_packages[@]}"; do
    boot_space_ok || break
    module="${entry%%|*}"; binary="${entry##*|}"
    if [[ -x "$BIN_DIR/$binary" ]]; then
      printf 'ALREADY INSTALLED  %s\n' "$binary" | tee -a "$REPORT_FILE"
    elif GOBIN="$BIN_DIR" go install "$module" > "$RUN_DIR/go-$binary.log" 2>&1; then
      printf 'INSTALLED  %s\n' "$binary" | tee -a "$REPORT_FILE"
    else
      printf 'FAILED  %s (see %s)\n' "$binary" "$RUN_DIR/go-$binary.log" | tee -a "$REPORT_FILE"
      failed=$((failed + 1))
      continue
    fi
    verify "$binary" "$binary"
  done
else
  printf 'SKIPPED  Go adapters: go is not installed (brew install go)\n' | tee -a "$REPORT_FILE"
fi

echo
echo "== Python adapters, each in its own venv =="
for entry in "${pip_packages[@]}"; do
  boot_space_ok || break
  package="${entry%%|*}"; binary="${entry##*|}"
  venv="$TOOLS_VENVS/$package"
  if [[ -x "$BIN_DIR/$binary" || -x "$venv/bin/$binary" ]]; then
    printf 'ALREADY INSTALLED  %s\n' "$package" | tee -a "$REPORT_FILE"
  else
    if [[ ! -x "$venv/bin/python" ]]; then
      "$TOOL_PYTHON" -m venv "$venv" > "$RUN_DIR/pyenv-$package.log" 2>&1 || {
        printf 'FAILED  %s venv creation (see %s)\n' "$package" "$RUN_DIR/pyenv-$package.log" | tee -a "$REPORT_FILE"
        failed=$((failed + 1)); continue; }
    fi
    if "$venv/bin/python" -m pip install --quiet --upgrade "$package" \
         > "$RUN_DIR/pip-$package.log" 2>&1; then
      printf 'INSTALLED  %s\n' "$package" | tee -a "$REPORT_FILE"
    else
      printf 'FAILED  %s (see %s)\n' "$package" "$RUN_DIR/pip-$package.log" | tee -a "$REPORT_FILE"
      failed=$((failed + 1)); rm -rf "$venv"; continue
    fi
  fi
  # Link the command this package is wanted for, then any console scripts it
  # declares. Never replace a real binary: a blanket link once shadowed
  # ProjectDiscovery httpx with the Python httpx library's CLI.
  link_script() {
    # Write a /bin/sh wrapper rather than a symlink. A pip console script carries
    # a "#!<venv>/bin/python" shebang, and a shebang cannot contain a space, so a
    # symlink to it fails outright when the project path has one.
    local name="$1" script="$venv/bin/$1"
    [[ -x "$script" ]] || return 0
    if [[ -e "$BIN_DIR/$name" && ! -L "$BIN_DIR/$name" ]] && ! head -1 "$BIN_DIR/$name" 2>/dev/null | grep -q '^#!/bin/sh'; then
      printf 'SKIPPED LINK  %s already exists in tools/bin as a real binary\n' "$name" | tee -a "$REPORT_FILE"
      return 0
    fi
    rm -f "$BIN_DIR/$name"
    {
      printf '#!/bin/sh\n'
      printf '# Generated by install_macos_arsenal.sh; runs the tool from its own venv.\n'
      printf 'exec "%s/bin/python" "%s/bin/%s" "$@"\n' "$venv" "$venv" "$name"
    } > "$BIN_DIR/$name"
    chmod +x "$BIN_DIR/$name"
  }
  link_script "$binary"
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    link_script "$name"
  done < <("$venv/bin/python" - "$package" <<'PYEOF'
import sys
from importlib.metadata import distribution, PackageNotFoundError
try:
    entries = distribution(sys.argv[1]).entry_points
except PackageNotFoundError:
    raise SystemExit(0)
for entry in entries:
    if entry.group == "console_scripts":
        print(entry.name)
PYEOF
)
  verify "$binary" "$package"
done

printf '\n%s\n' 'NOT INSTALLABLE THIS WAY ON macOS' | tee -a "$REPORT_FILE"
printf -- '- %s\n' "${unavailable[@]}" | tee -a "$REPORT_FILE"

printf '\n%s\n' \
  'An installed executable is not proof that a command, its credentials, or its' \
  'wordlists work. Open Security tools in HANZO and use Refresh catalog to see the' \
  'readiness this worker actually reports.' | tee -a "$REPORT_FILE"

echo
echo "Report: $REPORT_FILE"
if (( failed > 0 )); then
  echo "$failed item(s) failed or are not on PATH; their logs are retained in $RUN_DIR."
  exit 1
fi
echo "All requested tools installed and verified on PATH."

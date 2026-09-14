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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPORT_DIR="${PROJECT_DIR}/.hanzo-data"
BIN_DIR="${PROJECT_DIR}/tools/bin"
TOOLS_VENV="${PROJECT_DIR}/tools/pyenv"

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
)
if [[ "$ARCH" != "arm64" ]]; then
  release_binaries=(
    "epi052/feroxbuster|x86_64-macos-feroxbuster.tar.gz|feroxbuster"
    "hahwul/dalfox|*macos-x86_64.tar.gz|dalfox"
    "lc/gau|*darwin_amd64.tar.gz|gau"
  )
fi

# Homebrew formulas that back a bundled adapter. On macOS 13 and older Homebrew
# is a Tier 3 configuration and compiles these from source, so the heavyweight
# ones are kept out of --core deliberately.
brew_core=(
  nmap masscan rustscan arp-scan
  nikto amass fierce arjun
)
brew_full=(
  hydra john-jumbo hashcat
  gdb radare2 binwalk exiftool foremost
  trivy checkov terrascan prowler kube-bench
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

# Python adapters with no Homebrew formula. Installed into an isolated tools venv.
pip_core=(wafw00f dirsearch paramspider uro)
pip_full=(smbmap ropper volatility3 wfuzz)

# Adapters that are genuinely not installable this way on macOS.
unavailable=(
  "metasploit (msfconsole/msfvenom) - use the official macOS installer or a Kali VM"
  "zap (zap.sh) - install the OWASP ZAP desktop app: brew install --cask zap"
  "burpsuite - install Burp Suite and its MCP Server extension manually"
  "netexec / enum4linux / enum4linux-ng / responder / nbtscan / rpcclient - Linux-oriented SMB/AD tooling; use the Kali worker"
  "dirb / dotdotpwn / xsser / wpscan / steghide - no maintained macOS formula; use the Kali worker"
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
  printf 'Python plan:\n'; printf '  %s\n' "${pip_packages[@]}"
  printf 'Not installable on macOS:\n'; printf '  %s\n' "${unavailable[@]}"
  exit 0
fi

mkdir -p "$REPORT_DIR" "$BIN_DIR" || exit 1
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
echo "== Python adapters into an isolated venv =="
if [[ ! -x "$TOOLS_VENV/bin/python" ]]; then
  python3 -m venv "$TOOLS_VENV" > "$RUN_DIR/pyenv.log" 2>&1 || {
    printf 'FAILED  tools venv creation (see %s)\n' "$RUN_DIR/pyenv.log" | tee -a "$REPORT_FILE"
    failed=$((failed + 1))
  }
fi
if [[ -x "$TOOLS_VENV/bin/python" ]]; then
  for package in "${pip_packages[@]}"; do
    boot_space_ok || break
    if "$TOOLS_VENV/bin/python" -m pip install --quiet --upgrade "$package" > "$RUN_DIR/pip-$package.log" 2>&1; then
      printf 'INSTALLED  %s\n' "$package" | tee -a "$REPORT_FILE"
    else
      printf 'FAILED  %s (see %s)\n' "$package" "$RUN_DIR/pip-$package.log" | tee -a "$REPORT_FILE"
      failed=$((failed + 1))
      continue
    fi
    # Expose only the console scripts this package actually provides, and never
    # overwrite a real binary already in tools/bin. A blanket link here would
    # shadow ProjectDiscovery httpx with the Python httpx library's CLI.
    while IFS= read -r name; do
      [[ -z "$name" ]] && continue
      script="$TOOLS_VENV/bin/$name"
      [[ -x "$script" ]] || continue
      if [[ -e "$BIN_DIR/$name" && ! -L "$BIN_DIR/$name" ]]; then
        printf 'SKIPPED LINK  %s already exists in tools/bin as a real binary\n' \
          "$name" | tee -a "$REPORT_FILE"
        continue
      fi
      ln -sf "$script" "$BIN_DIR/$name"
    done < <("$TOOLS_VENV/bin/python" - "$package" <<'PYEOF'
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
  done
  for package in "${pip_packages[@]}"; do
    case "$package" in
      volatility3) verify "vol" "$package" ;;
      *) verify "$package" "$package" ;;
    esac
  done
fi

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

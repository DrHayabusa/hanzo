#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This installer is for an Ubuntu/Kali Linux lab VM."
  exit 1
fi

case "$(uname -m)" in
  x86_64) RELEASE_ARCH="amd64" ;;
  aarch64|arm64) RELEASE_ARCH="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

sudo apt-get update
sudo apt-get install -y curl jq unzip nmap

for package in gobuster ffuf nikto sqlmap dirsearch; do
  if apt-cache show "$package" >/dev/null 2>&1; then
    sudo apt-get install -y "$package"
  else
    echo "Skipping unavailable apt package: $package"
  fi
done

BIN_DIR="${VAPT_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"

install_projectdiscovery() {
  local repository="$1" binary="$2" archive download_url temp_dir
  temp_dir="$(mktemp -d -t vapt-linux-tool.XXXXXX)"
  archive="$temp_dir/$binary.zip"
  download_url="$(curl -fsSL "https://api.github.com/repos/$repository/releases/latest" \
    | jq -r --arg suffix "linux_${RELEASE_ARCH}.zip" '.assets[] | select(.name | endswith($suffix)) | .browser_download_url' \
    | head -1)"
  if [[ -z "$download_url" ]]; then
    echo "No compatible release found for $binary"
    rmdir "$temp_dir"
    return 1
  fi
  curl -fL "$download_url" -o "$archive"
  unzip -joq "$archive" "$binary" -d "$BIN_DIR"
  chmod +x "$BIN_DIR/$binary"
  unlink "$archive"
  rmdir "$temp_dir"
  echo "Installed $binary to $BIN_DIR"
}

install_projectdiscovery projectdiscovery/nuclei nuclei
install_projectdiscovery projectdiscovery/subfinder subfinder
install_projectdiscovery projectdiscovery/httpx httpx
install_projectdiscovery projectdiscovery/katana katana

echo "Add this to your shell profile if needed: export PATH=\"$BIN_DIR:\$PATH\""
echo "Installed tool versions:"
for tool in nmap gobuster ffuf nikto sqlmap dirsearch nuclei subfinder httpx katana; do
  command -v "$tool" >/dev/null 2>&1 && printf '  %s\n' "$tool"
done

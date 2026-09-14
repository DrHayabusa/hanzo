#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$PROJECT_DIR/tools/bin"
TEMP_DIR="$(mktemp -d -t vapt-tools.XXXXXX)"

cleanup() {
  case "$TEMP_DIR" in
    /var/folders/*/T/vapt-tools.*|/tmp/vapt-tools.*) rm -rf "$TEMP_DIR" ;;
  esac
}
trap cleanup EXIT

mkdir -p "$BIN_DIR"

install_zip() {
  local repo="$1" pattern="$2" binary="$3"
  local archive="$TEMP_DIR/$binary.zip"
  gh release download --repo "$repo" --pattern "$pattern" --output "$archive" --clobber
  unzip -joq "$archive" "$binary" -d "$BIN_DIR"
  chmod +x "$BIN_DIR/$binary"
  echo "Installed $binary"
}

install_tar() {
  local repo="$1" pattern="$2" binary="$3"
  local archive="$TEMP_DIR/$binary.tar.gz"
  gh release download --repo "$repo" --pattern "$pattern" --output "$archive" --clobber
  tar -xzf "$archive" -C "$TEMP_DIR" "$binary"
  mv "$TEMP_DIR/$binary" "$BIN_DIR/$binary"
  chmod +x "$BIN_DIR/$binary"
  echo "Installed $binary"
}

install_zip projectdiscovery/nuclei '*macOS_arm64.zip' nuclei
install_zip projectdiscovery/subfinder '*macOS_arm64.zip' subfinder
install_zip projectdiscovery/httpx '*macOS_arm64.zip' httpx
install_zip projectdiscovery/katana '*macOS_arm64.zip' katana
install_tar ffuf/ffuf '*macOS_arm64.tar.gz' ffuf
install_tar OJ/gobuster '*Darwin_arm64.tar.gz' gobuster

echo "Security tools installed in $BIN_DIR"

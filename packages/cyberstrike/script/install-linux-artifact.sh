#!/usr/bin/env bash
set -euo pipefail

# Install the Linux x64 archive produced by .github/workflows/build.yml.
# Keep the existing skill directory and merge the bundled catalog into it so
# user-added skills (including locally supplied WSTG skills) are not deleted.

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HOME_BIN="${CYBERSTRIKE_INSTALL_BIN_DIR:-$HOME/.local/bin}"
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
DATA_DIR="$DATA_HOME/cyberstrike"

for required in cyberstrike hackbrowser-worker.js data/scripts data/ebpf skill; do
  if [[ ! -e "$ROOT/$required" ]]; then
    echo "Required archive component missing: $ROOT/$required" >&2
    exit 1
  fi
done
if [[ ! -f "$ROOT/data/scripts/wayback_endpoints.py" ]]; then
  echo "Required helper missing: data/scripts/wayback_endpoints.py" >&2
  exit 1
fi
for required in cleanup.py dep_scan.py; do
  if [[ ! -f "$ROOT/data/ebpf/$required" ]]; then
    echo "Required eBPF program missing: data/ebpf/$required" >&2
    exit 1
  fi
done
if [[ ! -f "$ROOT/skill/SKILL_GUIDE.md" ]]; then
  echo "Skill catalog is incomplete: skill/SKILL_GUIDE.md is missing" >&2
  exit 1
fi

mkdir -p "$HOME_BIN" "$DATA_DIR/bin" "$DATA_DIR/data/scripts" "$DATA_DIR/data/ebpf" "$DATA_DIR/skill"

# install replaces an existing destination (including a previous regular binary)
# but doesn't touch the user's data directory.
install -m 0755 "$ROOT/cyberstrike" "$HOME_BIN/cyberstrike"
install -m 0644 "$ROOT/hackbrowser-worker.js" "$DATA_DIR/bin/hackbrowser-worker.js"

# Merge instead of deleting: retain skills added by the user, refresh bundled
# files shipped in this build, and copy in newly added catalog entries.
cp -a "$ROOT/skill/." "$DATA_DIR/skill/"
cp -a "$ROOT/data/scripts/." "$DATA_DIR/data/scripts/"
cp -a "$ROOT/data/ebpf/." "$DATA_DIR/data/ebpf/"

echo "CyberStrike installed: $HOME_BIN/cyberstrike"
echo "Skill catalog: $DATA_DIR/skill"
echo "Helper scripts: $DATA_DIR/data/scripts"
echo "eBPF scripts: $DATA_DIR/data/ebpf"
case ":$PATH:" in
  *":$HOME_BIN:"*) ;;
  *) echo "Add this to your shell profile if needed: export PATH=\"$HOME_BIN:\$PATH\"" ;;
esac
if [[ ! -d "$DATA_DIR/node_modules/playwright" ]]; then
  echo "Note: the hackbrowser browser worker needs Playwright installed under $DATA_DIR/node_modules."
  echo "For browser crawling, install it with: npm install --prefix \"$DATA_DIR\" --save-exact playwright@1.58.2"
  echo "Then install Chromium with: npx --prefix \"$DATA_DIR\" playwright install chromium"
fi

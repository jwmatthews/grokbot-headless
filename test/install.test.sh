#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
home_dir="$test_root/home"
fake_dir="$test_root/fake"
shim_dir="$test_root/bin"
mkdir -p "$home_dir" "$fake_dir/dist/local-exec-daemon" "$shim_dir"
printf 'setInterval(() => {}, 1000);\n' > "$fake_dir/dist/local-exec-daemon/main.cjs"
printf '{"version":"0.30.0"}\n' > "$fake_dir/package.json"
printf '#!/usr/bin/env sh\nexit 0\n' > "$shim_dir/systemctl"
chmod 0755 "$shim_dir/systemctl"
daemon_script="$fake_dir/dist/local-exec-daemon/main.cjs"
package_json="$fake_dir/package.json"

HOME="$home_dir" \
USER=testuser \
PATH="$shim_dir:$PATH" \
GROK_BOT_DAEMON_SCRIPT="$daemon_script" \
GROK_BOT_PACKAGE_JSON="$package_json" \
  "$repo_dir/install.sh"

test -x "$home_dir/.local/bin/grok-bot-headless"
test -x "$home_dir/.local/lib/grok-bot-headless/grok-bot-headless.mjs"
test -f "$home_dir/.config/systemd/user/grok-bot-headless.service"
test "$(stat -c '%a' "$home_dir/.config/grok-bot-headless/environment")" = 600
test "$(stat -c '%a' "$home_dir/.config/grok-bot-headless")" = 700
grep -q "^GROK_BOT_DAEMON_SCRIPT=\"$daemon_script\"$" "$home_dir/.config/grok-bot-headless/environment"
grep -q '^GROK_BOT_APP_ASAR="/opt/Grok Bot/resources/app.asar"$' "$home_dir/.config/grok-bot-headless/environment"
node_bin="$(node -p 'process.execPath')"
grep -q "^GROK_BOT_NODE=\"$node_bin\"$" "$home_dir/.config/grok-bot-headless/environment"
HOME="$home_dir" "$home_dir/.local/bin/grok-bot-headless" help >/dev/null
# The service runs the wrapper with systemd's short PATH, so the wrapper must work without node on PATH.
HOME="$home_dir" PATH=/usr/local/bin:/usr/bin GROK_BOT_NODE="$node_bin" "$home_dir/.local/bin/grok-bot-headless" help >/dev/null
check_output="$(
  HOME="$home_dir" \
  GROK_BOT_DAEMON_SCRIPT="$daemon_script" \
  GROK_BOT_PACKAGE_JSON="$package_json" \
  SAND_CLIENT_APP_VERSION="99.0.0" \
    "$home_dir/.local/bin/grok-bot-headless" check --local
)"
[[ "$check_output" == *'"compatible": true'* ]]
[[ "$check_output" == *'"installedVersion": "99.0.0"'* ]]
[[ "$check_output" == *'"testedVersion": false'* ]]
if HOME="$home_dir" \
  GROK_BOT_DAEMON_SCRIPT="$fake_dir/dist/local-exec-daemon/missing.cjs" \
  GROK_BOT_PACKAGE_JSON="$package_json" \
    "$home_dir/.local/bin/grok-bot-headless" check --local >/dev/null 2>&1; then
  printf 'compatibility check accepted a missing daemon entry point\n' >&2
  exit 1
fi
if HOME="$home_dir" \
  GROK_BOT_APP_ASAR="$fake_dir/package.json" \
    "$home_dir/.local/bin/grok-bot-headless" check --local >/dev/null 2>&1; then
  printf 'compatibility check accepted a file that is not an asar archive\n' >&2
  exit 1
fi
mkdir -p "$home_dir/.local/share/grok-bot-headless"
printf '{}\n' > "$home_dir/.config/grok-bot-headless/credentials.json"
printf '{"pid":%s}\n' "$$" > "$home_dir/.local/share/grok-bot-headless/local-exec-daemon.json"
if HOME="$home_dir" PATH="$shim_dir:$PATH" "$home_dir/.local/bin/grok-bot-headless" logout >/dev/null 2>&1; then
  printf 'logout accepted an active daemon\n' >&2
  exit 1
fi
test -f "$home_dir/.config/grok-bot-headless/credentials.json"
rm -f "$home_dir/.local/share/grok-bot-headless/local-exec-daemon.json"
HOME="$home_dir" PATH="$shim_dir:$PATH" "$home_dir/.local/bin/grok-bot-headless" logout >/dev/null
test ! -e "$home_dir/.config/grok-bot-headless/credentials.json"

HOME="$home_dir" PATH="$shim_dir:$PATH" "$repo_dir/uninstall.sh" --purge
test ! -e "$home_dir/.local/bin/grok-bot-headless"
test ! -e "$home_dir/.local/lib/grok-bot-headless"
test ! -e "$home_dir/.config/grok-bot-headless"

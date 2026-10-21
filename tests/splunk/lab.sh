#!/usr/bin/env bash
# Local Splunk validation lab. Search-time TA configuration only; no vendor inputs or scripts.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMAGE="splunk/splunk:10.6.0.5"
NAME="adm-splunk-lab"
SECRETS="${ADM_LAB_SECRETS:-$HERE/.lab-secrets}"
EXTRACTED="$ROOT/research/extracted"
TAS=(
  "splunk-add-on-for-stream-wire-data_816/Splunk_TA_stream_wire_data"
  "cisco-security-cloud_372/CiscoSecurityCloud"
  "cisco-dc-networking_122/cisco_dc_networking_app_for_splunk"
  "cisco-enterprise-networking-add-on-for-splunk_4060/TA_cisco_catalyst"
  "cisco-enterprise-networking-netflow-add-on-for-splunk_400/splunk_app_stream_ipfix_cisco_hsl"
  "cisco-meraki-add-on-for-splunk_350/Splunk_TA_cisco_meraki"
)
VENDOR_APP="cisco-enterprise-networking-app-for-splunk_4020/cisco-catalyst-app"
SEARCH_TIME_CONFS=(props transforms eventtypes tags fields macros collections ipfixmap)
LAB_INDEXES=(netflow cisco_dc cisco_secure_fw cisco_isovalent cisco_catalyst cisco_meraki k8s otel_traces cilium_hubble adm_summary adm_summary_v2 adm adm_alt_nf adm_alt_nd adm_alt_x adm_alt_y)

py() { python3 "$HERE/lab.py" "$@"; }

# Staging holds the rendered HEC token. A RETURN trap is skipped when set -e
# exits the shell, so cleanup is bound to process exit and fatal signals.
STAGE=""
cleanup_stage() { [[ -z "$STAGE" ]] || rm -rf "$STAGE"; }
trap cleanup_stage EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Re-exec under the cooperative lock. The token is inherited by nested lab
# subprocesses; the lock itself remains held by the wrapper process.
if ! python3 "$ROOT/tools/lab_lock.py" --root "$ROOT" --check-owned; then
  exec python3 "$ROOT/tools/lab_lock.py" --root "$ROOT" -- "$0" "$@"
fi

wait_healthy() {
  local deadline=$((SECONDS + 1200)) status
  while ((SECONDS < deadline)); do
    status="$(docker inspect -f '{{.State.Health.Status}}' "$NAME" 2>/dev/null || echo missing)"
    case "$status" in
      healthy) py wait; echo "Splunk is ready."; return 0 ;;
      missing) echo "container $NAME is not running" >&2; return 1 ;;
    esac
    sleep 10
  done
  echo "timed out waiting for $NAME to become healthy" >&2
  return 1
}

cmd_up() {
  py init-secrets
  if docker inspect "$NAME" >/dev/null 2>&1; then
    docker start "$NAME" >/dev/null
  else
    # --env-file keeps the generated password out of the process list and stdout.
    docker run -d --name "$NAME" --platform linux/amd64 \
      -p 127.0.0.1:8000:8000 -p 127.0.0.1:8089:8089 -p 127.0.0.1:8088:8088 \
      -e SPLUNK_START_ARGS=--accept-license \
      -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
      --env-file "$SECRETS" \
      "$IMAGE" >/dev/null
  fi
  wait_healthy
}

copy_ta() {
  local src="$1" dest="$2" conf
  mkdir -p "$dest/default"
  cp "$src/default/app.conf" "$dest/default/app.conf"
  for conf in "${SEARCH_TIME_CONFS[@]}"; do
    [[ -f "$src/default/$conf.conf" ]] && cp "$src/default/$conf.conf" "$dest/default/"
  done
  if [[ -d "$src/lookups" ]]; then
    mkdir -p "$dest/lookups"
    find "$src/lookups" -maxdepth 1 -type f \( -name '*.csv' -o -name '*.csv.gz' \) \
      -exec cp {} "$dest/lookups/" \;
  fi
  if [[ -d "$src/metadata" ]]; then
    mkdir -p "$dest/metadata"
    find "$src/metadata" -maxdepth 1 -type f -name '*.meta' -exec cp {} "$dest/metadata/" \;
  fi
}

cmd_install() {
  local stage ta
  STAGE="$(mktemp -d)"
  stage="$STAGE"
  chmod 700 "$stage"
  for ta in "${TAS[@]}"; do
    [[ -d "$EXTRACTED/$ta" ]] || { echo "missing $EXTRACTED/$ta" >&2; return 1; }
    copy_ta "$EXTRACTED/$ta" "$stage/$(basename "$ta")"
  done
  # Co-install the dashboard app separately from Atlas. Its scheduled lookup
  # writers stay disabled until explicitly dispatched by a qualification test.
  [[ -d "$EXTRACTED/$VENDOR_APP" ]] || { echo "missing $EXTRACTED/$VENDOR_APP" >&2; return 1; }
  cp -R "$EXTRACTED/$VENDOR_APP" "$stage/cisco-catalyst-app"
  python3 - "$stage/cisco-catalyst-app" <<'PY'
import re
import sys
from pathlib import Path

app = Path(sys.argv[1])
# Splunk permits unindented backslash continuations that ConfigParser rejects.
# Only stanza names are needed to disable every vendor writer.
searches = re.findall(r"(?m)^\[([^\r\n\]]+)\]\s*$", (app / "default/savedsearches.conf").read_text())
local = app / "local"
local.mkdir(exist_ok=True)
(local / "savedsearches.conf").write_text(
    "\n".join(
        f"[{name}]\ndisabled = 1\nenableSched = 0\n"
        for name in dict.fromkeys(searches)
    )
)
PY
  # Final qualification installs the retained exact archive; source remains useful for development.
  if [[ -n "${ADM_LAB_PACKAGE:-}" ]]; then
    python3 "$ROOT/tools/stage_lab_package.py" "$ADM_LAB_PACKAGE" "$stage"
  else
    cp -R "$ROOT/splunk_app/splunk_adm" "$stage/splunk_adm"
    cp "$ROOT/config/deployment-health.json" "$stage/splunk_adm/bin/adm_settings_registry.json"
  fi
  cp -R "$HERE/lab_app" "$stage/adm_lab"
  # Keep the private staging root closed while ordinary app content receives
  # its existing install modes. Render credentials only after this pass.
  find "$stage" -mindepth 1 -type d -exec chmod 755 {} +
  find "$stage" -type f -exec chmod 644 {} +
  python3 - "$SECRETS" "$stage/adm_lab/default" <<'PY'
import os
from pathlib import Path
import stat
import sys

try:
    descriptor = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("unsafe secret file")
        contents = stream.read(65537)
    if len(contents) > 65536:
        raise ValueError("oversized secret file")
    tokens = [line.partition("=")[2] for line in contents.splitlines() if line.startswith("HEC_TOKEN=")]
    if len(tokens) != 1 or not tokens[0] or "\0" in tokens[0]:
        raise ValueError("invalid HEC configuration")
    default = Path(sys.argv[2])
    template = default / "inputs.conf.template"
    text = template.read_text()
    if text.count("@HEC_TOKEN@") != 1:
        raise ValueError("invalid HEC template")
    descriptor = os.open(default / "inputs.conf", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(text.replace("@HEC_TOKEN@", tokens[0]))
    template.unlink()
except Exception:
    # Secret contents and parser exceptions must never reach installation logs.
    raise SystemExit("Unable to render private lab HEC configuration") from None
PY
  for app in "$stage"/*; do
    docker exec -u root "$NAME" rm -rf "/opt/splunk/etc/apps/$(basename "$app")"
    docker cp "$app" "$NAME:/opt/splunk/etc/apps/$(basename "$app")" >/dev/null
  done
  docker exec -u root "$NAME" chown -R splunk:splunk /opt/splunk/etc/apps
  echo "Installed: $(cd "$stage" && echo *). Restarting Splunk..."
  py restart
  echo "Splunk restarted."
}

cmd_reset() {
  local splunk="/opt/splunk/bin/splunk" index
  docker exec -u splunk "$NAME" "$splunk" stop >/dev/null
  for index in "${LAB_INDEXES[@]}"; do
    docker exec -u splunk "$NAME" "$splunk" clean eventdata -index "$index" -f >/dev/null
  done
  docker exec -u splunk "$NAME" "$splunk" start --answer-yes --no-prompt >/dev/null
  py wait
  echo "Cleared event data in: ${LAB_INDEXES[*]}"
}

cmd_down() {
  docker rm -f -v "$NAME" >/dev/null 2>&1 || true
  echo "Removed container $NAME and its volumes."
}

cmd_purge() {
  cmd_down
  docker rmi "$IMAGE" >/dev/null 2>&1 || true
  rm -f "$SECRETS"
  echo "Removed image $IMAGE and lab secrets."
}

case "${1:-}" in
  up) cmd_up ;;
  install) cmd_install ;;
  load) shift; py load "$@" ;;
  search) shift; py search "$@" ;;
  saved) shift; py saved "$@" ;;
  btool) docker exec -u splunk "$NAME" /opt/splunk/bin/splunk btool check ;;
  reset) cmd_reset ;;
  down) cmd_down ;;
  purge) cmd_purge ;;
  *)
    echo "usage: $0 {up|install|load <ndjson...>|search '<spl>' [earliest] [latest]|saved <name> [earliest] [latest]|btool|reset|down|purge}" >&2
    exit 2
    ;;
esac

#!/usr/bin/env bash
# Local Splunk validation lab. Search-time TA configuration only; no vendor inputs or scripts.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMAGE="splunk/splunk:10.6.0.5"
NAME="adm-splunk-lab"
SECRETS="$HERE/.lab-secrets"
EXTRACTED="$ROOT/research/extracted"
TAS=(
  "splunk-add-on-for-stream-wire-data_816/Splunk_TA_stream_wire_data"
  "cisco-security-cloud_372/CiscoSecurityCloud"
  "cisco-dc-networking_122/cisco_dc_networking_app_for_splunk"
)
SEARCH_TIME_CONFS=(props transforms eventtypes tags fields macros)
LAB_INDEXES=(netflow cisco_dc cisco_secure_fw cisco_isovalent k8s otel_traces adm_summary adm)

py() { python3 "$HERE/lab.py" "$@"; }

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
  local stage ta token
  stage="$(mktemp -d)"
  trap 'rm -rf "$stage"' RETURN
  for ta in "${TAS[@]}"; do
    [[ -d "$EXTRACTED/$ta" ]] || { echo "missing $EXTRACTED/$ta" >&2; return 1; }
    copy_ta "$EXTRACTED/$ta" "$stage/$(basename "$ta")"
  done
  # Install the source app (not a possibly stale dist/stage copy) so tests see current knowledge objects.
  cp -R "$ROOT/splunk_app/splunk_adm" "$stage/splunk_adm"
  cp -R "$HERE/lab_app" "$stage/adm_lab"
  token="$(sed -n 's/^HEC_TOKEN=//p' "$SECRETS")"
  sed "s/@HEC_TOKEN@/$token/" "$stage/adm_lab/default/inputs.conf.template" \
    >"$stage/adm_lab/default/inputs.conf"
  rm "$stage/adm_lab/default/inputs.conf.template"
  find "$stage" -type d -exec chmod 755 {} + && find "$stage" -type f -exec chmod 644 {} +
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

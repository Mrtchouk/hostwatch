#!/usr/bin/env bash
# hostwatch installer. Run as root from a checkout.
#
#   ./install.sh              install or upgrade
#   ./install.sh --uninstall  remove everything except reports and baselines
set -euo pipefail

PREFIX=${PREFIX:-/opt/hostwatch}
CONFDIR=${CONFDIR:-/etc/hostwatch}
SPOOL=${SPOOL:-/var/spool/hostwatch/requests}
BINDIR=${BINDIR:-/usr/local/bin}
LIB=${LIB:-/var/lib/hostwatch}
UNITDIR=${UNITDIR:-/etc/systemd/system}
SRC=$(cd "$(dirname "$0")" && pwd)

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

if [ "${1:-}" = --uninstall ]; then
  systemctl disable --now hostwatch.timer hostwatch-watch.timer hostwatch-agent.path 2>/dev/null || true
  rm -f "$UNITDIR"/hostwatch*.{service,timer,path}
  systemctl daemon-reload
  rm -rf "$PREFIX" "$BINDIR/hostwatch"
  echo "removed. state kept in $LIB and config in $CONFDIR"
  exit 0
fi

missing=()
for c in bash jq curl awk sed find flock sha256sum; do command -v "$c" >/dev/null || missing+=("$c"); done
if [ ${#missing[@]} -gt 0 ]; then
  echo "missing: ${missing[*]}" >&2
  echo "on Debian or Ubuntu: apt install jq curl util-linux coreutils" >&2
  exit 1
fi

install -d "$BINDIR" "$PREFIX/bin" "$PREFIX/share" "$CONFDIR" "$SPOOL" \
           "$LIB"/{baseline,scans,reports,outbox,replies,pending,state,tmp}
install -m 755 "$SRC"/bin/hostwatch*        "$PREFIX/bin/"
install -m 644 "$SRC"/share/rules.json      "$PREFIX/share/"
ln -sf "$PREFIX/bin/hostwatch" "$BINDIR/hostwatch"

install -m 644 "$SRC/hostwatch.conf.example" "$CONFDIR/hostwatch.conf.example"

if [ ! -f "$CONFDIR/hostwatch.conf" ]; then
  # Inspect the host and write a configuration that matches it. A generic
  # example config produces findings about services that are not installed and
  # silence about the ones that are, which is worse than no tool at all.
  "$PREFIX/bin/hostwatch-detect" > "$CONFDIR/hostwatch.conf"
  chmod 640 "$CONFDIR/hostwatch.conf"
  # shellcheck source=/dev/null
  . "$CONFDIR/hostwatch.conf"
  echo "Detected on this host:"
  printf '  services   %s\n' "${HW_SERVICES[*]:-none}"
  printf '  web roots  %s\n' "${#HW_WEBROOTS[@]} found"
  printf '  secrets    %s\n' "${#HW_SECRET_FILES[@]} found"
  printf '  sites      %s\n' "${#HW_SITES[@]} from enabled vhosts"
  [ -n "${HW_PM2_USER:-}" ] && printf '  pm2        %s (%s)\n' "${HW_PM2_APPS[*]:-no app}" "$HW_PM2_USER"
  [ "${HW_MYSQL:-0}" = 1 ] && printf '  database   reachable, checks enabled\n'
  echo
  echo "Written to $CONFDIR/hostwatch.conf. Read it once: what it could not guess"
  echo "is HW_URLS_FORBIDDEN, the endpoints that must never answer 200."
else
  echo "Kept your $CONFDIR/hostwatch.conf. New options are in hostwatch.conf.example."
  echo "Re-run $PREFIX/bin/hostwatch-detect to see what this host looks like now."
fi

chmod 700 "$LIB/baseline"
chmod 755 "$LIB" "$LIB/scans" "$LIB/reports" "$LIB/replies" "$LIB/outbox" "$LIB/pending"

for u in "$SRC"/systemd/*; do
  install -d "$UNITDIR"
  sed "s|/opt/hostwatch|$PREFIX|g" "$u" > "$UNITDIR/$(basename "$u")"
done
systemctl daemon-reload
systemctl enable --now hostwatch.timer hostwatch-watch.timer hostwatch-agent.path >/dev/null

echo
echo "Seeding baselines. The first run records the current state as reference,"
echo "so make sure this host is in a state you trust."
"$PREFIX/bin/hostwatch-scan" --mode full --quiet >/dev/null 2>&1 || true

cat <<EOF

Installed.
  config    $CONFDIR/hostwatch.conf
  state     $LIB
  command   hostwatch

  hostwatch          last verdict
  hostwatch now      scan and analyse now
  hostwatch status   timers and queue
EOF

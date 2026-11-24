#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

declare -A HOST=(
  [joplin]=192.168.50.191 [matrix]=192.168.50.192 [nextcloud]=192.168.50.195
  [mass]=192.168.20.225 [ollama]=192.168.10.101 [librenms]=192.168.50.15
)
declare -A DIR=(
  [joplin]=/opt/joplin-server [matrix]=/opt/matrix
  [nextcloud]=/opt/nextcloud [mass]=/opt/music-assistant
)
declare -A OLD=(
  [joplin]='tee[[:space:]]+/opt/joplin-server/\*'
  [matrix]='tee[[:space:]]+/opt/matrix/\*'
  [nextcloud]='tee[[:space:]]+/opt/nextcloud/\*'
  [mass]='tee[[:space:]]+/opt/music-assistant/\*'
  [ollama]='ollama-install-staging/install\.sh'
  [librenms]='mysql[[:space:]]+-u[[:space:]]+root[[:space:]]+librenms'
)
NEWFILE_PREFIX=/etc/sudoers.d/rbd-update-bot-phase0

rules_for() {
  local d="${DIR[$1]:-}"
  if [ -n "$d" ]; then
    local c="$d/docker-compose[.]yml" e="$d/[.]env"
    cat <<R
rbdroot ALL=(root) NOPASSWD: /usr/bin/tee ^$c[.]new\$
rbdroot ALL=(root) NOPASSWD: /usr/bin/cp ^$c[.]new $c\$
rbdroot ALL=(root) NOPASSWD: /usr/bin/cp ^$c $c[.]bak-[0-9]+\$
rbdroot ALL=(root) NOPASSWD: /usr/bin/rm ^$c[.]new\$
rbdroot ALL=(root) NOPASSWD: /usr/bin/tee ^$e[.]new\$
rbdroot ALL=(root) NOPASSWD: /usr/bin/cp ^$e[.]new $e\$
rbdroot ALL=(root) NOPASSWD: /usr/bin/cp ^$e $e[.]bak-[0-9]+\$
rbdroot ALL=(root) NOPASSWD: /usr/bin/rm ^$e[.]new\$
R
    if [ "$1" = mass ]; then
      cat <<R
rbdroot ALL=(root) NOPASSWD: /usr/bin/cp ^$d/data/library[.]db[.]backup $d/data/library[.]db\$
rbdroot ALL=(root) NOPASSWD: /usr/bin/rm ^$d/data/library[.]db-wal $d/data/library[.]db-shm -f\$
R
    fi
  elif [ "$1" = ollama ]; then
    echo '# Managed by rbd-update-bot scripts/install_phase0_sudoers.sh'
    echo 'rbdroot ALL=(root) NOPASSWD: /usr/local/sbin/rbd-ollama-install ""'
  fi
}

checks_for() {
  local d="${DIR[$1]:-}"
  if [ -n "$d" ]; then
    local c="$d/docker-compose.yml"
    echo "ALLOW|/usr/bin/tee $c.new"
    echo "ALLOW|/usr/bin/cp $c.new $c"
    echo "ALLOW|/usr/bin/cp $c $c.bak-203"
    echo "ALLOW|/usr/bin/rm $c.new"
    echo "ALLOW|/usr/bin/cp $d/.env $d/.env.bak-203"
    echo "DENY|/usr/bin/tee $d/../../etc/sudoers.d/rbd-probe"
    echo "DENY|/usr/bin/tee $c.new /etc/shadow"
    echo "DENY|/usr/bin/cp /etc/shadow $c"
    echo "DENY|/usr/bin/rm -rf $d/data"
    echo "DENY|/usr/bin/chown rbdroot $c"
    if [ "$1" = mass ]; then
      echo "ALLOW|/usr/bin/cp $d/data/library.db.backup $d/data/library.db"
      echo "ALLOW|/usr/bin/rm $d/data/library.db-wal $d/data/library.db-shm -f"
    fi
  elif [ "$1" = ollama ]; then
    echo "ALLOW|/usr/local/sbin/rbd-ollama-install"
    echo "DENY|/usr/local/sbin/rbd-ollama-install --anything"
    echo "DENY|/usr/bin/sh /home/rbdroot/ollama-install-staging/install.sh"
  elif [ "$1" = librenms ]; then
    echo "DENY|/usr/bin/mysql -u root librenms -e select"
  fi
}

remote_script() {
  local svc="$1" rules helper_b64="" NEWFILE="$NEWFILE_PREFIX-$1"
  rules="$(rules_for "$svc")"
  [ "$svc" = ollama ] && helper_b64="$(base64 -w0 "$HERE/host-files/rbd-ollama-install")"
  cat <<EOF
set -euo pipefail
BK=/root/sudoers-backup-\$(date +%Y%m%d-%H%M%S)
mkdir -p "\$BK" && cp -a /etc/sudoers.d "\$BK/" && echo "backup: \$BK"
restore() { echo "!! visudo -c failed -- restoring \$BK"; rm -f $NEWFILE; cp -a "\$BK/sudoers.d/." /etc/sudoers.d/; visudo -c; exit 1; }

if [ -n "$helper_b64" ]; then
  echo "$helper_b64" | base64 -d > /usr/local/sbin/rbd-ollama-install.tmp
  install -o root -g root -m 0755 /usr/local/sbin/rbd-ollama-install.tmp /usr/local/sbin/rbd-ollama-install
  rm -f /usr/local/sbin/rbd-ollama-install.tmp
  echo "installed /usr/local/sbin/rbd-ollama-install"
fi

RULES=\$(cat <<'RULES_EOF'
$rules
RULES_EOF
)
if [ -n "\$RULES" ]; then
  T=\$(mktemp); printf '%s\n' "\$RULES" > "\$T"
  visudo -cf "\$T" >/dev/null || { echo "new rules failed visudo -- aborting, nothing changed"; rm -f "\$T"; exit 1; }
  install -o root -g root -m 0440 "\$T" $NEWFILE; rm -f "\$T"
  echo "installed $NEWFILE"
fi

for f in \$(grep -lE '${OLD[$svc]}' /etc/sudoers.d/* 2>/dev/null | grep -v '^$NEWFILE\$' || true); do
  echo; echo "old grant found in \$f:"
  grep -nE '${OLD[$svc]}' "\$f" | grep -v '^[0-9]*:[[:space:]]*#' | sed 's/^/    /'
  read -r -p "comment out the line(s) above? [y/N] " ans < /dev/tty
  [ "\$ans" = y ] || { echo "  left unchanged"; continue; }
  T=\$(mktemp); sed -E '\%${OLD[$svc]}%{/^[[:space:]]*#/!s/^/# disabled 2026-11-20 by bot-service-identity Phase 0: /}' "\$f" > "\$T"
  visudo -cf "\$T" >/dev/null || { echo "  edited copy failed visudo -- left unchanged"; rm -f "\$T"; continue; }
  install -o root -g root -m 0440 "\$T" "\$f"; rm -f "\$T"; echo "  disabled"
done

visudo -c >/dev/null || restore
echo "visudo -c: OK"
EOF
}

targets=("$@"); [ ${#targets[@]} -eq 0 ] && targets=(joplin matrix nextcloud mass ollama librenms)
for svc in "${targets[@]}"; do
  h="${HOST[$svc]:-}"; [ -z "$h" ] && { echo "unknown service: $svc"; continue; }
  echo; echo "=== $svc ($h) ==="
  b64="$(remote_script "$svc" | base64 -w0)"
  ssh -t "rbdroot@$h" "T=\$(mktemp) && echo '$b64' | base64 -d > \"\$T\" && sudo bash \"\$T\"; rc=\$?; rm -f \"\$T\"; exit \$rc" \
    || echo "!! $svc: install step failed -- see above"
done

echo; echo "=== verification (sudo -n -l: checks only, runs nothing) ==="
fail=0
for svc in "${targets[@]}"; do
  h="${HOST[$svc]:-}"; [ -z "$h" ] && continue
  while IFS='|' read -r want cmd; do
    if ssh -n -o BatchMode=yes "rbdroot@$h" "sudo -n -ll $cmd" 2>/dev/null | grep -q '!authenticate'; then got=ALLOW; else got=DENY; fi
    if [ "$got" = "$want" ]; then echo "  ok   $svc  $got  $cmd"; else echo "  FAIL $svc  $got (want $want)  $cmd"; fail=1; fi
  done < <(checks_for "$svc")
done
[ $fail -eq 0 ] && echo "all checks passed" || { echo "SOME CHECKS FAILED"; exit 1; }

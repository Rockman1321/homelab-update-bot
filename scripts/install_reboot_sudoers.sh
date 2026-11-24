#!/usr/bin/env bash
set -euo pipefail

RULE='rbdroot ALL=(root) NOPASSWD: /usr/bin/systemctl reboot'
FILE=/etc/sudoers.d/rbd-update-bot-reboot

declare -A HOSTS=(
  [immich]="immich.example.com"
  [nextcloud]="nextcloud.example.com"
  [joplin]="joplin.example.com"
  [matrix]="matrix.example.com"
  [discourse]="192.168.50.193"
  [mass]="192.168.20.225"
)

targets=("${!HOSTS[@]}")
if [ "$#" -gt 0 ]; then
  targets=("$@")
fi

for name in "${targets[@]}"; do
  host="${HOSTS[$name]:-}"
  if [ -z "$host" ]; then
    echo "=== $name: unknown service name, skipping ==="
    continue
  fi
  echo "=== $name ($host) ==="
  ssh -t "rbdroot@${host}" "
    set -e
    TMP=\$(mktemp)
    echo '${RULE}' > \"\$TMP\"
    if ! sudo visudo -cf \"\$TMP\"; then
      echo 'SYNTAX CHECK FAILED -- not installing on this host'
      rm -f \"\$TMP\"
      exit 1
    fi
    if sudo test -f ${FILE} && sudo diff -q \"\$TMP\" ${FILE} >/dev/null 2>&1; then
      echo 'already present, skipping'
      rm -f \"\$TMP\"
    else
      sudo install -o root -g root -m 0440 \"\$TMP\" ${FILE}
      rm -f \"\$TMP\"
      echo 'installed'
    fi
  "
done

echo
echo "Verifying (checks the real NOPASSWD listing without actually rebooting anything):"
for name in "${targets[@]}"; do
  host="${HOSTS[$name]:-}"
  [ -z "$host" ] && continue
  echo -n "  $name: "
  ssh "rbdroot@${host}" "sudo -n -l 2>&1 | grep -q 'NOPASSWD.*systemctl reboot' && echo OK || echo 'still needs a password'"
done

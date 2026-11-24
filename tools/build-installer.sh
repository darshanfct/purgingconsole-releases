#!/usr/bin/env bash
# build-installer.sh — regenerate install-purging-console.sh (the one-paste installer) from purging-console.sh.
# The installer writes the new version to a temp file, checks it, then renames it over the old one,
# so a running copy (the service) is never rewritten underneath itself; a running service is restarted.
set -euo pipefail
cd "$(dirname "$0")/.."
grep -q '^ENDOFSCRIPT$' purging-console.sh && { echo "purging-console.sh contains the heredoc marker" >&2; exit 1; }
{
  echo '# Purging Management Console — installer. Paste into a root shell.'
  echo 'PC_NEW=/usr/local/bin/purgingconsole.new.$$'
  echo "cat > \"\$PC_NEW\" << 'ENDOFSCRIPT'"
  cat purging-console.sh
  echo 'ENDOFSCRIPT'
  cat <<'X'
if chmod 755 "$PC_NEW" && bash -n "$PC_NEW" && mv -f "$PC_NEW" /usr/local/bin/purgingconsole; then
  echo "OK — installed: $(/usr/local/bin/purgingconsole --version)"
  if systemctl is-active --quiet purging-console 2>/dev/null; then
    systemctl restart purging-console && echo "The running purge service was restarted on the new version."
  fi
  /usr/local/bin/purgingconsole
else
  rm -f "$PC_NEW"; echo "Install FAILED — the previous version was left in place." >&2
fi
X
} > install-purging-console.sh
bash -n install-purging-console.sh
sha256sum purging-console.sh > purging-console.sh.sha256      # checked by "purgingconsole --update"
echo "install-purging-console.sh rebuilt ($(wc -l < install-purging-console.sh) lines), purging-console.sh.sha256 written"

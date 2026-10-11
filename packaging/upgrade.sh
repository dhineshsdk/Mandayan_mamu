#!/usr/bin/env bash
# Upgrade an installed Sutra from a newer offline bundle. Takes a backup first; see docs/operations.md.
#
#   sudo ./upgrade.sh [--prefix P] [--etc E] [--user U] [--no-user] [--no-systemd]
set -euo pipefail

bundle="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
prefix=/opt/sutra etc=/etc/sutra user=sutra use_user=1 use_systemd=1
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) prefix="$2"; shift 2 ;;
    --etc) etc="$2"; shift 2 ;;
    --user) user="$2"; shift 2 ;;
    --no-user) use_user=0; shift ;;
    --no-systemd) use_systemd=0; shift ;;
    -h|--help) sed -n '2,5p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
die() { echo "upgrade: $*" >&2; exit 1; }

[ -x "$prefix/venv/bin/python" ] || die "no installation at $prefix. Use install.sh."
( cd "$bundle" && sha256sum --quiet -c SHA256SUMS ) || die "the bundle is damaged or was changed."
installed_tag="$("$prefix/venv/bin/python" -c 'import sys;print(f"py{sys.version_info.major}{sys.version_info.minor}")')"
[ "$(cat "$bundle/PYTHON_TAG")" = "$installed_tag" ] || die "this bundle was built for a different Python than the installed one ($installed_tag)."

run_sutra() {
  local loader="set -a; . '$etc/sutra.env'; exec \"\$@\""
  local cmd=("$prefix/venv/bin/python" -m sutra "$@")
  if [ "$use_user" = 1 ]; then
    runuser -u "$user" -- env -i PATH="$PATH" bash -c "$loader" _ "${cmd[@]}"
  else
    env -i PATH="$PATH" bash -c "$loader" _ "${cmd[@]}"
  fi
}

old="$(cat "$prefix/VERSION" 2>/dev/null || echo unknown)"
new="$(cat "$bundle/VERSION")"
echo "Upgrading Sutra $old -> $new"
if [ "$use_systemd" = 1 ]; then systemctl stop sutra; fi
"$prefix/venv/bin/pip" install --quiet --no-index --find-links "$bundle/wheelhouse" --upgrade sutra
if ! run_sutra upgrade --passphrase-file "$etc/backup.pass"; then
  echo "The database upgrade failed and the service is still stopped. Follow the 'Restore with' line above, reinstall" >&2
  echo "the previous bundle with install.sh, then start the service." >&2
  exit 1
fi
echo "$new" > "$prefix/VERSION"
mkdir -p "$prefix/docs"
cp -r "$bundle/docs/." "$prefix/docs/"
if [ "$use_systemd" = 1 ]; then systemctl start sutra; fi
echo "Sutra $new is installed."

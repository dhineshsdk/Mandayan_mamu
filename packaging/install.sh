#!/usr/bin/env bash
# Install Sutra from the offline bundle. Needs no internet access.
#
#   sudo ./install.sh                       # /opt/sutra, /var/lib/sutra, /etc/sutra, user "sutra", systemd units
#   ./install.sh --prefix P --data D --etc E --backups B --no-user --no-systemd    # a trial install, no root needed
#
# Safe to run again: it never overwrites an existing sutra.env or the data folder.
set -euo pipefail

bundle="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
prefix=/opt/sutra data=/var/lib/sutra etc=/etc/sutra backups=/var/backups/sutra user=sutra
use_user=1 use_systemd=1 python="${PYTHON:-python3}"

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) prefix="$2"; shift 2 ;;
    --data) data="$2"; shift 2 ;;
    --etc) etc="$2"; shift 2 ;;
    --backups) backups="$2"; shift 2 ;;
    --user) user="$2"; shift 2 ;;
    --python) python="$2"; shift 2 ;;
    --no-user) use_user=0; shift ;;
    --no-systemd) use_systemd=0; shift ;;
    -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

die() { echo "install: $*" >&2; exit 1; }

[ -d "$bundle/wheelhouse" ] || die "wheelhouse/ not found next to install.sh. Run it from the unpacked bundle."
echo "Checking the bundle against SHA256SUMS ..."
( cd "$bundle" && sha256sum --quiet -c SHA256SUMS ) || die "the bundle is damaged or was changed. Copy it again and compare the .sha256 file."

command -v "$python" >/dev/null || die "$python not found. Install the Python version this bundle was built for ($(cat "$bundle/PYTHON_TAG"))."
have="$("$python" -c 'import sys;print(f"py{sys.version_info.major}{sys.version_info.minor}")')"
want="$(cat "$bundle/PYTHON_TAG")"
[ "$have" = "$want" ] || die "this bundle was built for $want but $python is $have. Ask for a bundle built for $have."
"$python" -c 'import venv, ensurepip' 2>/dev/null || die "the Python venv module is missing (Debian/Ubuntu: apt install python3-venv)."

if [ "$use_user" = 1 ]; then
  [ "$(id -u)" = 0 ] || die "run as root (sudo) to create the service user, or pass --no-user for a trial install."
  id "$user" >/dev/null 2>&1 || useradd --system --home-dir "$data" --no-create-home --shell /usr/sbin/nologin "$user"
  owner="$user:$user"
else
  owner="$(id -un):$(id -gn)"
fi

echo "Installing into $prefix ..."
mkdir -p "$prefix"
"$python" -m venv "$prefix/venv"
"$prefix/venv/bin/pip" install --quiet --no-index --find-links "$bundle/wheelhouse" sutra
version="$(cat "$bundle/VERSION")"
echo "$version" > "$prefix/VERSION"

umask 077
mkdir -p "$data" "$backups" "$etc"
chown "$owner" "$data" "$backups"
chmod 700 "$data" "$backups"

if [ ! -e "$etc/sutra.env" ]; then
  secret="$("$prefix/venv/bin/python" -c 'import secrets;print(secrets.token_urlsafe(48))')"
  backup_pass="$("$prefix/venv/bin/python" -c 'import secrets;print(secrets.token_urlsafe(32))')"
  sed -e "s|@DATA@|$data|g" -e "s|@BACKUPS@|$backups|g" -e "s|@SECRET@|$secret|g" \
      "$bundle/sutra.env.example" > "$etc/sutra.env"
  printf '%s\n' "$backup_pass" > "$etc/backup.pass"
  echo "Wrote $etc/sutra.env and $etc/backup.pass (new secrets)."
else
  echo "Kept the existing $etc/sutra.env."
fi
if [ "$use_user" = 1 ]; then
  chown "root:$user" "$etc" "$etc/sutra.env" "$etc/backup.pass"
  chmod 750 "$etc"
  chmod 640 "$etc/sutra.env" "$etc/backup.pass"
fi

# Run a sutra command with the service's identity and environment file.
run_sutra() {
  local loader="set -a; . '$etc/sutra.env'; exec \"\$@\""
  local cmd=("$prefix/venv/bin/python" -m sutra "$@")
  if [ "$use_user" = 1 ]; then
    runuser -u "$user" -- env -i PATH="$PATH" HOME="$data" bash -c "$loader" _ "${cmd[@]}"
  else
    env -i PATH="$PATH" HOME="$data" bash -c "$loader" _ "${cmd[@]}"
  fi
}

echo "Creating the database ..."
run_sutra db-upgrade

if [ "$use_systemd" = 1 ]; then
  command -v systemctl >/dev/null || die "systemctl not found; pass --no-systemd and run Sutra your own way."
  for unit in sutra.service sutra-backup.service sutra-backup.timer; do
    sed -e "s|@PREFIX@|$prefix|g" -e "s|@DATA@|$data|g" -e "s|@BACKUPS@|$backups|g" -e "s|@ETC@|$etc|g" \
        -e "s|@USER@|$user|g" "$bundle/systemd/$unit" > "/etc/systemd/system/$unit"
  done
  systemctl daemon-reload
  systemctl enable sutra.service sutra-backup.timer >/dev/null
  systemctl start sutra-backup.timer
fi

mkdir -p "$prefix/docs"
cp -r "$bundle/docs/." "$prefix/docs/"
cp "$bundle/nginx.conf.example" "$prefix/nginx.conf.example"

echo
echo "Sutra $version is installed. Next:"
echo "  1. Create the first administrator (it asks for a password):"
echo "       cd $data && set -a && . $etc/sutra.env && set +a && sudo -E -u $user $prefix/venv/bin/python -m sutra create-admin --email you@example.in --name 'Your Name'"
echo "  2. Put TLS in front (see $prefix/nginx.conf.example) and set SUTRA_BASE_URL in $etc/sutra.env."
echo "  3. Start it:  systemctl start sutra"
echo "  4. Sign in, open Administration -> Modules and licences and install your licence key."
echo "  5. Check the installation with 'python -m sutra doctor' (see $prefix/docs/installation.md)."
echo "  6. Copy $etc/backup.pass to a safe place OFF this server. Without it the backups cannot be read."

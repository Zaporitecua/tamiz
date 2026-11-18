"""POSIX shell scripts run on the WAF host (or inside the WAF container).

Every transport executes these same scripts, so the behaviour that matters
for safety lives in one place:

* Files are written to a temporary name *inside the destination directory*
  and renamed over the final name. A rename within one directory is atomic,
  and the new file gets the SELinux label of its directory. Staging files in
  /tmp and moving them is not safe: ``mv`` across filesystems keeps the
  source label (``user_tmp_t``), nginx cannot open the files, and ModSecurity
  skips them without any error.
* After the rename, ``restorecon`` normalises the label when SELinux is on.
* The temporary name starts with a dot and does not end in ``.conf``, so an
  ``Include .../*.conf`` can never pick it up half-written.
* Content travels base64-encoded inside the command, which keeps stdin free
  for ``sudo -S`` and works through ``docker exec`` without a TTY.

Requirements on the far side: sh, base64, stat, mv, chmod (coreutils or
BusyBox).
"""

READ_FILES = r"""
for p in "$@"; do
  if [ -f "$p" ]; then
    if [ -r "$p" ]; then
      printf '%s\tok\t' "$p"; base64 < "$p" | tr -d '\n'; printf '\n'
    else
      printf '%s\tunreadable\t\n' "$p"
    fi
  elif [ -e "$p" ]; then
    printf '%s\tnotfile\t\n' "$p"
  else
    printf '%s\tmissing\t\n' "$p"
  fi
done
"""

GLOB = r"""
LC_ALL=C; export LC_ALL
IFS='
'
for pat in "$@"; do
  for f in $pat; do
    if [ -e "$f" ]; then printf '%s\t%s\n' "$pat" "$f"; fi
  done
done
"""

# Atomic write. $2 is the whole content in base64, or "-" when the content
# was already sent with WRITE_CHUNK (files larger than one command line can
# carry: Linux limits a single argument to 128 KiB).
WRITE_FILE = r"""
set -e
dst=$1; b64=$2; mkdirs=$3
dir=${dst%/*}; base=${dst##*/}
[ -n "$dir" ] || dir=/
selinux_on() { command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; }
if [ ! -d "$dir" ]; then
  if [ "$mkdirs" = 1 ]; then
    mkdir -p "$dir"; chmod 755 "$dir"; echo "mkdir=$dir"
    if selinux_on && command -v restorecon >/dev/null 2>&1; then restorecon "$dir" 2>/dev/null || true; fi
  else
    echo "directory not found: $dir" >&2; exit 3
  fi
fi
tmp="$dir/.$base.tamiz-tmp"
trap 'rm -f "$tmp"' EXIT
umask 022
if [ "$b64" = "-" ]; then
  [ -f "$tmp" ] || { echo "temporary file missing: $tmp" >&2; exit 4; }
else
  printf '%s' "$b64" | base64 -d > "$tmp"
fi
if [ -e "$dst" ]; then
  mode=$(stat -c %a "$dst" 2>/dev/null || echo 644)
  owner=$(stat -c %u:%g "$dst" 2>/dev/null || echo "")
  chmod "$mode" "$tmp"
  if [ -n "$owner" ]; then chown "$owner" "$tmp" 2>/dev/null || true; fi
else
  chmod 644 "$tmp"
fi
mv -f "$tmp" "$dst"
trap - EXIT
if selinux_on; then
  if command -v restorecon >/dev/null 2>&1; then
    if restorecon -F "$dst" 2>/dev/null; then echo "selinux=relabeled"; else echo "selinux=relabel-failed"; fi
  else
    echo "selinux=no-restorecon"
  fi
  echo "label=$(stat -c %C "$dst" 2>/dev/null || true)"
else
  echo "selinux=off"
fi
"""

# One part of a large file, appended to the same temporary file WRITE_FILE
# uses. $3 = 1 for the first part (creates the directory if allowed and
# truncates the temporary file). On any failure the temporary file is removed.
WRITE_CHUNK = r"""
set -e
dst=$1; b64=$2; first=$3; mkdirs=$4
dir=${dst%/*}; base=${dst##*/}
[ -n "$dir" ] || dir=/
tmp="$dir/.$base.tamiz-tmp"
trap 'rm -f "$tmp"' EXIT
if [ "$first" = 1 ]; then
  if [ ! -d "$dir" ]; then
    if [ "$mkdirs" = 1 ]; then
      mkdir -p "$dir"; chmod 755 "$dir"; echo "mkdir=$dir"
      if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v restorecon >/dev/null 2>&1; then
        restorecon "$dir" 2>/dev/null || true
      fi
    else
      echo "directory not found: $dir" >&2; exit 3
    fi
  fi
  umask 022
  : > "$tmp"
fi
[ -f "$tmp" ] || { echo "temporary file missing: $tmp" >&2; exit 4; }
printf '%s' "$b64" | base64 -d >> "$tmp"
trap - EXIT
"""

DISCARD_TMP = r"""
dst=$1
dir=${dst%/*}; base=${dst##*/}
[ -n "$dir" ] || dir=/
rm -f "$dir/.$base.tamiz-tmp"
"""

REMOVE_FILE = r"""
set -e
if [ -e "$1" ]; then rm -f -- "$1"; echo "removed"; else echo "absent"; fi
"""

SELINUX_VERIFY = r"""
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
  echo "selinux=on"
  for p in "$@"; do
    if [ ! -e "$p" ]; then printf '%s\tmissing\t\n' "$p"; continue; fi
    label=$(stat -c %C "$p" 2>/dev/null || true)
    if command -v restorecon >/dev/null 2>&1; then
      out=$(restorecon -n -v "$p" 2>&1 || true)
      if [ -n "$out" ]; then
        printf '%s\tmislabeled\t%s\t%s\n' "$p" "$label" "$(printf '%s' "$out" | tr '\n\t' '  ')"
      else
        printf '%s\tok\t%s\n' "$p" "$label"
      fi
    else
      printf '%s\tunknown\t%s\n' "$p" "$label"
    fi
  done
else
  echo "selinux=off"
fi
"""

SELINUX_SCAN_DIRS = r"""
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v restorecon >/dev/null 2>&1; then
  for d in "$@"; do
    [ -d "$d" ] && restorecon -n -v -R "$d" 2>&1 | head -n 200
  done
  echo "selinux=on"
else
  echo "selinux=off"
fi
"""

DIAGNOSE = r"""
echo "user=$(id -un 2>/dev/null || whoami 2>/dev/null)"
echo "uid=$(id -u 2>/dev/null)"
echo "kernel=$(uname -sr 2>/dev/null)"
if [ -r /etc/os-release ]; then . /etc/os-release; echo "os=${PRETTY_NAME:-unknown}"; fi
for c in base64 stat mv chmod restorecon selinuxenabled nginx apachectl httpd caddy; do
  if command -v "$c" >/dev/null 2>&1; then echo "cmd.$c=$(command -v "$c")"; fi
done
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
  echo "selinux=$(getenforce 2>/dev/null || echo on)"
else
  echo "selinux=off"
fi
for d in "$@"; do
  if [ -d "$d" ]; then
    w=no; [ -w "$d" ] && w=yes
    printf 'dir\t%s\texists\t%s\t%s\n' "$d" "$w" "$(stat -c '%U:%G %a' "$d" 2>/dev/null)"
  else
    parent=${d%/*}
    pw=no; [ -w "$parent" ] && pw=yes
    printf 'dir\t%s\tmissing\t%s\t\n' "$d" "$pw"
  fi
done
"""

WRITABLE = r"""
# For each target file: can this user create a file in its directory and
# rename over it? (args: mkdirs flag, then paths)
mkdirs=$1; shift
for p in "$@"; do
  dir=${p%/*}; [ -n "$dir" ] || dir=/
  if [ -d "$dir" ]; then
    if [ -w "$dir" ]; then printf '%s\tok\n' "$p"; else printf '%s\tdir_not_writable\t%s\n' "$p" "$(stat -c '%U:%G %a' "$dir" 2>/dev/null)"; fi
  else
    parent=$dir
    while [ ! -d "$parent" ]; do parent=${parent%/*}; [ -n "$parent" ] || parent=/; done
    if [ "$mkdirs" = 1 ] && [ -w "$parent" ]; then printf '%s\tok\n' "$p"
    elif [ "$mkdirs" = 1 ]; then printf '%s\tparent_not_writable\t%s\n' "$p" "$parent"
    else printf '%s\tdir_missing\t%s\n' "$p" "$dir"; fi
  fi
done
"""

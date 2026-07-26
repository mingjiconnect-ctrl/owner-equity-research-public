#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 7 || "$(id -u)" -ne 0 || "$(uname -s)" != Linux ]]; then
  echo "usage: phase5e_candidate_exec.sh CANDIDATE INTERFACE VENV SCRATCH ORACLE CWD COMMAND..." >&2
  exit 2
fi

candidate=$(realpath "$1")
interface=$(realpath "$2")
venv=$(realpath "$3")
scratch=$(realpath "$4")
oracle=$(realpath "$5")
candidate_cwd=$6
shift 6

case "$candidate_cwd" in
  /work|/work/*) ;;
  *) echo "candidate working directory escapes /work" >&2; exit 2 ;;
esac
[[ -d "$candidate/.git" && -f "$interface/kernel-release-interface.json" ]]
[[ -x "$venv/bin/python" && -d "$scratch" && -d "$oracle" ]]

exec unshare --mount --net --ipc --uts --pid --fork --kill-child bash -ceu '
  candidate=$1
  interface=$2
  venv=$3
  scratch=$4
  oracle=$5
  candidate_cwd=$6
  shift 6

  mount --make-rprivate /
  root=$(mktemp -d /tmp/phase5e-candidate-root.XXXXXX)
  mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$root"
  mkdir -p \
    "$root/work" "$root/interface" "$root/venv" "$root/scratch" "$root/oracle" \
    "$root/candidate-import/owner_research" "$root/candidate-import/scripts" \
    "$root/candidate-import/tests" \
    "$root/audit-bin" "$root/usr" "$root/bin" "$root/lib" "$root/lib64" \
    "$root/opt" "$root/dev" "$root/proc" "$root/tmp" "$root/etc" "$root/.old-root"

  mount --bind "$candidate" "$root/work"
  mount -o remount,ro,bind "$root/work"
  mount --bind "$interface" "$root/interface"
  mount -o remount,ro,bind "$root/interface"
  mount --bind "$venv" "$root/venv"
  mount -o remount,ro,bind "$root/venv"
  mount --bind "$scratch" "$root/scratch"
  mount --bind "$oracle" "$root/oracle"
  mount -o remount,ro,bind "$root/oracle"
  mount --bind "$candidate/src/owner_research" "$root/candidate-import/owner_research"
  mount -o remount,ro,bind "$root/candidate-import/owner_research"
  mount --bind "$candidate/scripts" "$root/candidate-import/scripts"
  mount -o remount,ro,bind "$root/candidate-import/scripts"
  mount --bind "$candidate/tests" "$root/candidate-import/tests"
  mount -o remount,ro,bind "$root/candidate-import/tests"
  mount --bind /usr "$root/usr"
  mount -o remount,ro,bind "$root/usr"
  mount --bind /bin "$root/bin"
  mount -o remount,ro,bind "$root/bin"
  mount --bind /lib "$root/lib"
  mount -o remount,ro,bind "$root/lib"
  if [[ -d /lib64 ]]; then
    mount --bind /lib64 "$root/lib64"
    mount -o remount,ro,bind "$root/lib64"
  fi
  if [[ -d /opt ]]; then
    mount --bind /opt "$root/opt"
    mount -o remount,ro,bind "$root/opt"
  fi
  : > "$root/dev/null"
  : > "$root/dev/urandom"
  mount --bind /dev/null "$root/dev/null"
  mount --bind /dev/urandom "$root/dev/urandom"
  mount -t proc -o nosuid,nodev,noexec proc "$root/proc"
  mount -t tmpfs -o mode=1777,nosuid,nodev,noexec tmpfs "$root/tmp"
  printf "nobody:x:65534:65534:nobody:/scratch:/usr/sbin/nologin\n" > "$root/etc/passwd"
  printf "nogroup:x:65534:\n" > "$root/etc/group"
  printf "hosts: files\n" > "$root/etc/nsswitch.conf"
  cp "$oracle/scripts/phase5e_kernel_git_shim.sh" "$root/audit-bin/git"
  chmod 0555 "$root/audit-bin/git"

  pivot_root "$root" "$root/.old-root"
  umount -l /.old-root
  rmdir /.old-root

  ulimit -c 0
  ulimit -f 32768
  ulimit -n 256
  ulimit -u 256
  ulimit -v 4194304
  cd "$candidate_cwd"
  exec timeout --signal=TERM --kill-after=10s 15m \
    setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
    env -i \
      HOME=/scratch/home \
      GIT_OPTIONAL_LOCKS=0 \
      LANG=C.UTF-8 \
      LC_ALL=C.UTF-8 \
      PATH=/audit-bin:/venv/bin:/usr/bin:/bin \
      OWNER_VALUATION_REPO=/interface/kernel \
      PYTHONDONTWRITEBYTECODE=1 \
      PYTHONHASHSEED=0 \
      PYTHONNOUSERSITE=1 \
      PYTHONPYCACHEPREFIX=/scratch/pycache \
      PYTHONSAFEPATH=1 \
      PYTEST_ADDOPTS="--import-mode=importlib -p no:cacheprovider" \
      PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
      PYTHONPATH=/oracle:/work/src:/work:/work/tests:/oracle/tests \
      PIP_CONFIG_FILE=/dev/null \
      PIP_NO_INDEX=1 \
      PHASE5E_CANDIDATE_REPOSITORY=/work \
      RUFF_CACHE_DIR=/scratch/ruff-cache \
      TMPDIR=/scratch/tmp \
      AUDIT_CANDIDATE_SANDBOX=linux-pivot-root-netless-v1 \
      "$@"
' bash "$candidate" "$interface" "$venv" "$scratch" "$oracle" "$candidate_cwd" "$@"

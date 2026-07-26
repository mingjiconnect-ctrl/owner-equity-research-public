#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 7 ]]; then
  echo "usage: $0 CONTROL_REPO CANDIDATE_REPO KERNEL_INTERFACE VENV RUNTIME_ID REVIEWED_COMMIT RUNTIME" >&2
  exit 2
fi

control_repo=$(realpath "$1")
candidate_repo=$(realpath "$2")
kernel_interface=$(realpath "$3")
venv=$(realpath "$4")
runtime_id=$5
reviewed_commit=$6
runtime=$(realpath -m "$7")

if [[ "$(id -u)" -ne 0 || "$(uname -s)" != Linux ]]; then
  echo "acceptance audit launcher requires root on Linux" >&2
  exit 2
fi
if [[ ! "$reviewed_commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid reviewed commit" >&2
  exit 2
fi
if [[ ! "$runtime_id" =~ ^cp(311|312|313)$ ]]; then
  echo "invalid protected runtime identity" >&2
  exit 2
fi
for repository in "$control_repo" "$candidate_repo"; do
  [[ -d "$repository/.git" ]]
  [[ -z "$(git -C "$repository" remote)" ]]
  [[ -z "$(git -C "$repository" for-each-ref --format='%(refname)')" ]]
  [[ -z "$(git -C "$repository" status --porcelain=v1)" ]]
done
[[ "$(git -C "$candidate_repo" rev-parse HEAD)" == "$reviewed_commit" ]]
[[ -x "$venv/bin/python" ]]

"$venv/bin/python" -I "$control_repo/scripts/verify_kernel_release_interface.py" \
  --interface "$kernel_interface" >/dev/null
"$venv/bin/python" -I -S "$control_repo/scripts/verify_phase5e_candidate_import_surface.py" \
  --repository "$candidate_repo" >/dev/null

if [[ -e "$runtime" ]]; then
  echo "audit runtime must not already exist" >&2
  exit 2
fi
install -d -m 0700 "$runtime"
install -d -m 0700 "$runtime/final" "$runtime/oracle"
install -d -m 0755 -o 0 -g 0 "$runtime/candidate-scratch"
install -d -m 0750 -o 65534 -g 65534 \
  "$runtime/candidate-scratch/home" \
  "$runtime/candidate-scratch/tmp" \
  "$runtime/candidate-scratch/pycache" \
  "$runtime/candidate-scratch/ruff-cache"
install -d -m 1770 -o 0 -g 65534 "$runtime/candidate-scratch/controller-outputs"
install -m 0660 -o 0 -g 65534 /dev/null \
  "$runtime/candidate-scratch/controller-outputs/phase5e-test-counts.json"
install -m 0660 -o 0 -g 65534 /dev/null \
  "$runtime/candidate-scratch/controller-outputs/phase5e-independent.xml"
date -u +%Y-%m-%dT%H:%M:%SZ > "$runtime/final/started_at"
chmod 0600 "$runtime/final/started_at"

# Only this bounded oracle surface is visible in the candidate rootfs.  The full control checkout
# and the root-owned final evidence directory are never mounted for the candidate UID.
install -d -m 0755 "$runtime/oracle/scripts" "$runtime/oracle/tests"
install -m 0555 "$control_repo/scripts/phase5e_kernel_git_shim.sh" \
  "$runtime/oracle/scripts/phase5e_kernel_git_shim.sh"
install -m 0444 "$control_repo/scripts/verify_phase5e2b12a_semantic_oracle.py" \
  "$runtime/oracle/scripts/verify_phase5e2b12a_semantic_oracle.py"
install -m 0444 "$control_repo/scripts/verify_phase5e2b12b_semantic_oracle.py" \
  "$runtime/oracle/scripts/verify_phase5e2b12b_semantic_oracle.py"
install -m 0444 "$control_repo/scripts/verify_phase5e2b12c_semantic_oracle.py" \
  "$runtime/oracle/scripts/verify_phase5e2b12c_semantic_oracle.py"
install -m 0444 "$control_repo/scripts/verify_phase5e2c0_semantic_oracle.py" \
  "$runtime/oracle/scripts/verify_phase5e2c0_semantic_oracle.py"
install -m 0444 "$control_repo/scripts/verify_phase5e_successor_gate.py" \
  "$runtime/oracle/scripts/verify_phase5e_successor_gate.py"
install -m 0444 "$control_repo/scripts/verify_phase5e_successor_gate_oracle.py" \
  "$runtime/oracle/scripts/verify_phase5e_successor_gate_oracle.py"
install -m 0444 "$control_repo/scripts/phase5e-successor-gate-bundle.schema.json" \
  "$runtime/oracle/scripts/phase5e-successor-gate-bundle.schema.json"
install -m 0444 "$control_repo/scripts/phase5e2b12b-acceptance-trust.json" \
  "$runtime/oracle/scripts/phase5e2b12b-acceptance-trust.json"
install -m 0444 "$control_repo/scripts/phase5e_audit_profiles.py" \
  "$runtime/oracle/scripts/phase5e_audit_profiles.py"
successor_oracle="governance/phase5e-gates/phase5e2b12c/semantic-oracle.py.txt"
if [[ -f "$control_repo/$successor_oracle" ]]; then
  install -D -m 0444 "$control_repo/$successor_oracle" "$runtime/oracle/$successor_oracle"
fi
install -m 0444 "$control_repo/component-lock.json" "$runtime/oracle/component-lock.json"
while IFS= read -r -d "" relative; do
  install -D -m 0444 "$control_repo/$relative" "$runtime/oracle/$relative"
done < <(git -C "$control_repo" ls-files -z -- tests)
python -I - "$runtime/oracle" <<'PY'
import hashlib
import json
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
entries = []
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    if path.is_dir():
        continue
    relative = path.relative_to(root).as_posix()
    mode = path.lstat().st_mode
    if relative == "oracle-manifest.json" or path.is_symlink() or not stat.S_ISREG(mode):
        raise SystemExit("control oracle surface contains an unexpected file type")
    entries.append({"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
manifest = {"schema_version": "1.0.0", "files": entries}
(root / "oracle-manifest.json").write_text(
    json.dumps(manifest, allow_nan=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
chmod 0444 "$runtime/oracle/oracle-manifest.json"

chown -R root:root "$control_repo" "$candidate_repo" "$kernel_interface" "$venv"
chmod -R a-w "$control_repo" "$candidate_repo" "$kernel_interface" "$venv"
chown -R root:root "$runtime/final" "$runtime/oracle"

set +e
unshare --mount --net --pid --fork --kill-child --mount-proc bash -ceu '
  mount --make-rprivate /
  for readonly_tree in "$1" "$2" "$3" "$4"; do
    mount --bind "$readonly_tree" "$readonly_tree"
    mount -o remount,ro,bind "$readonly_tree"
  done
  ulimit -c 0
  ulimit -f 32768
  ulimit -n 512
  ulimit -u 512
  exec timeout --signal=TERM --kill-after=30s 60m \
    setpriv --no-new-privs env -i \
      HOME="$6/final" \
      GIT_OPTIONAL_LOCKS=0 \
      LANG=C.UTF-8 \
      LC_ALL=C.UTF-8 \
      PATH="$4/bin:/usr/bin:/bin" \
      PYTHONDONTWRITEBYTECODE=1 \
      PYTHONPYCACHEPREFIX="$6/final/controller-pycache" \
      TMPDIR="$6/final" \
      PHASE5E_AUDIT_STARTED_AT="$(cat "$6/final/started_at")" \
      AUDIT_OS_SANDBOX=linux-root-controller-net-pid-v2 \
      PHASE5E_CANDIDATE_EXEC="$1/scripts/phase5e_candidate_exec.sh" \
      PHASE5E_CANDIDATE_REPOSITORY="$2" \
      PHASE5E_KERNEL_INTERFACE="$3" \
      PHASE5E_AUDIT_VENV="$4" \
      PHASE5E_CANDIDATE_SCRATCH="$6/candidate-scratch" \
      PHASE5E_CONTROL_ORACLE="$6/oracle" \
      "$4/bin/python" -I "$1/scripts/run_phase5e_audit.py" \
        --repository "$2" \
        --kernel-interface "$3" \
        --reviewed-commit "$5" \
        --runtime-id "$7" \
        --output "$6/final/findings.json" \
        --require-os-sandbox
' bash \
  "$control_repo" "$candidate_repo" "$kernel_interface" "$venv" \
  "$reviewed_commit" "$runtime" "$runtime_id" \
  > "$runtime/final/controller.log" 2>&1
controller_status=$?
set -e

for evidence in \
  "$runtime/final/findings.json" \
  "$runtime/final/phase5e-independent.xml" \
  "$runtime/final/phase5e-nodeids.txt"; do
  if [[ ! -e "$evidence" ]]; then
    install -m 0600 -o 0 -g 0 /dev/null "$evidence"
  fi
  [[ -f "$evidence" && ! -L "$evidence" ]]
  chmod 0600 "$evidence"
  [[ "$(stat -c %u "$evidence")" == 0 ]]
  [[ "$(stat -c %a "$evidence")" == 600 ]]
  [[ "$(stat -c %h "$evidence")" == 1 ]]
done
[[ "$(stat -c %s "$runtime/final/findings.json")" -le 4194304 ]]
[[ "$(stat -c %s "$runtime/final/phase5e-independent.xml")" -le 16777216 ]]
[[ "$(stat -c %s "$runtime/final/phase5e-nodeids.txt")" -le 4194304 ]]
[[ "$(stat -c %s "$runtime/final/controller.log")" -le 1048576 ]]
sha256sum "$runtime/final/controller.log" > "$runtime/final/controller.log.sha256"
chmod 0600 "$runtime/final/controller.log" "$runtime/final/controller.log.sha256"
exit "$controller_status"

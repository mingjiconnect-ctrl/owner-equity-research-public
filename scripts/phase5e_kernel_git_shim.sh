#!/usr/bin/env bash
set -euo pipefail

kernel_root=/interface/kernel
commit=be9b0773d5a78f5f8a33ba982494512668df85fe
tag=v2.0.0-rc.2
tag_object=4e19ce6a59bc4321ebcd368e807ed764f4e8abde

if [[ "${1:-}" == "-C" && "${2:-}" == "$kernel_root" ]]; then
  shift 2
  if [[ "$#" -eq 2 && "$1" == "rev-parse" && "$2" == "HEAD" ]]; then
      printf '%s\n' "$commit"
      exit 0
  elif [[ "$#" -eq 2 && "$1" == "rev-parse" && "$2" == "$tag" ]]; then
      printf '%s\n' "$tag_object"
      exit 0
  elif [[ "$#" -eq 2 && "$1" == "rev-parse" && "$2" == "$tag^{}" ]]; then
      printf '%s\n' "$commit"
      exit 0
  elif [[ "$#" -eq 3 && "$1" == "cat-file" && "$2" == "-t" && "$3" == "$tag" ]]; then
      printf 'tag\n'
      exit 0
  elif [[ "$#" -eq 2 && "$1" == "status" && \
          ( "$2" == "--porcelain" || "$2" == "--porcelain=v1" ) ]]; then
      exit 0
  elif [[ "$#" -eq 1 && "$1" == "remote" ]]; then
      exit 0
  fi
  printf 'kernel release-interface Git query is not allowlisted: %q ' "$@" >&2
  printf '\n' >&2
  exit 64
fi

exec /usr/bin/git -c safe.directory=/work "$@"

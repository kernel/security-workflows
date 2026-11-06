#!/usr/bin/env bash
# Reads NUL-delimited paths on stdin and prints, NUL-delimited, the ones the
# container remediation workflow must not publish.
set -euo pipefail

while IFS= read -r -d '' path; do
  case "${path##*/}" in
    go.mod | go.sum | Dockerfile | Dockerfile.* | *.Dockerfile) continue ;;
  esac
  printf '%s\0' "$path"
done

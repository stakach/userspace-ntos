#!/usr/bin/env bash
# Layout rule for the executive's target module tree (issue #382, owner ruling 3):
# no `static` under the new directories except the executor-local block.
#
# Globals ported into these directories become fields of an owner struct. The one
# exception is a non-`mut` static of type `ExecutorLocal`, which holds the state of
# the thread running executive code.
#
#   scripts/check_executive_layout_statics.sh [executive-src-dir]
set -euo pipefail

SRC="${1:-$(cd "$(dirname "$0")/.." && pwd)/components/ntos-executive/src}"
LAYOUT_DIRS=(boot ingress executor syscall ob cm io pnp driver_host ps mm lpc win32k
  storage ke diag)

# A static item: the keyword, optional `mut`, a name, then `:`. A lifetime
# (`&'static T`) is preceded by `'` and never matches. Comment lines are skipped.
STATIC_ITEM="(^|[^'[:alnum:]_])static[[:space:]]+(mut[[:space:]]+)?[A-Za-z_\$][A-Za-z0-9_]*[[:space:]]*:"
ALLOWED="(^|[^'[:alnum:]_])static[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*:[[:space:]]*ExecutorLocal[[:space:]]*="

checked=0
violations=""
for dir in "${LAYOUT_DIRS[@]}"; do
  [ -d "$SRC/$dir" ] || continue
  checked=$((checked + 1))
  found="$(grep -rnE --include='*.rs' "$STATIC_ITEM" "$SRC/$dir" \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' \
    | grep -vE "$ALLOWED" || true)"
  [ -z "$found" ] || violations+="$found"$'\n'
done

if [ "$checked" -eq 0 ]; then
  echo "no target-layout directory found under $SRC" >&2
  exit 2
fi
# Positive control: the block itself must be found, so a pattern that stops
# matching on this grep cannot pass silently.
blocks="$(grep -rnE --include='*.rs' "$ALLOWED" "$SRC/executor" 2>/dev/null \
  | grep -cvE '^[^:]+:[0-9]+:[[:space:]]*//' || true)"
if [ "$blocks" -ne 1 ]; then
  echo "expected exactly one ExecutorLocal static under $SRC/executor, found $blocks" >&2
  exit 1
fi
if [ -n "$violations" ]; then
  echo "static items are not allowed under the executive's target-layout directories" >&2
  echo "(move the state into an owner struct, or into ExecutorLocal if it is executor-local):" >&2
  printf '%s' "$violations" >&2
  exit 1
fi
echo "executive layout statics: ok ($checked target-layout director$([ "$checked" -eq 1 ] && echo y || echo ies) checked)"

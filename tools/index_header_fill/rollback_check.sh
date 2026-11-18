#!/bin/bash
# rollback_check.sh <scratch>: the build BEFORE the index header fill still
# reads and writes a datadir the fill has filled.
#
#   OLD_PYTHONPATH  ouroboros src + sync site of the previous build
#   NEW_PYTHONPATH  ouroboros src + sync site of this build
#   PY              python (the ouroboros venv's)
#
# The old build writes the #52 shape, the new build fills it, the old build
# reads it (metadata must equal an unfilled control copy), rewrites a row on
# both copies with its own #52 writer (must stay equal; the header must
# survive), and the new build re-opens it.  Negative control: a rewrite on
# the control alone must show up as DIFFERENT.  <scratch> is wiped.
set -euo pipefail
S=$1; D=$(cd "$(dirname "$0")" && pwd); STEP=$D/rollback_check.py
FIX=$D/../../tests/fixtures/index_header_fill/core31_chain.json
: "${OLD_PYTHONPATH:?}" "${NEW_PYTHONPATH:?}" "${PY:=python3}"
old() { PYTHONPATH=$OLD_PYTHONPATH "$PY" "$STEP" "$@" 2>/dev/null; }
new() { PYTHONPATH=$NEW_PYTHONPATH "$PY" "$STEP" "$@" 2>/dev/null; }
same() { python3 -c 'import json,sys; a,b=(json.load(open(f)) for f in sys.argv[1:3]); print("IDENTICAL" if a["entries"]==b["entries"] else "DIFFERENT")' "$1" "$2"; }
rm -rf "$S"; mkdir -p "$S"
old make "$S/db" "$FIX"
cp -a "$S/db" "$S/control"
old dump "$S/control" > "$S/control.json"
new fill "$S/db" "$FIX"
old dump "$S/db" > "$S/old-reads-filled.json"
echo "old build reads the filled datadir: metadata $(same "$S/control.json" "$S/old-reads-filled.json")"
old write "$S/db" 60; old write "$S/control" 60 > /dev/null
old dump "$S/db" > "$S/a.json"; old dump "$S/control" > "$S/c.json"
echo "after the old build rewrites h60 on both: metadata $(same "$S/a.json" "$S/c.json")"
new fill "$S/db" "$FIX"
new dump "$S/db" > "$S/re.json"
echo "new build re-opens it: metadata $(same "$S/c.json" "$S/re.json")"
old write "$S/control" 61 > /dev/null
old dump "$S/control" > "$S/neg.json"
echo "negative control (control rewritten at h61 alone): metadata $(same "$S/neg.json" "$S/re.json")"

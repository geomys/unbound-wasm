#!/bin/sh
# update-embedded.sh copies a freshly built module over the embedded
# unbound.wasm and pins its hash in module.go, where TestEmbeddedModuleHash
# checks it.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SRC=${1:-$ROOT/build/work/unbound.wasm}

cp "$SRC" "$ROOT/unbound.wasm"
HASH=$(sha256sum "$SRC" | cut -d' ' -f1)

python3 - "$ROOT/module.go" "$HASH" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
text, n = re.subn(r'const moduleSHA256 = "[0-9a-f]+"',
                  f'const moduleSHA256 = "{sys.argv[2]}"', text)
if n != 1:
    raise SystemExit("moduleSHA256 declaration not found exactly once")
path.write_text(text)
PY

gofmt -w "$ROOT/module.go"

#!/bin/sh
# build-module.sh compiles the embedded unbound.wasm module: it downloads
# the pinned Unbound release, applies the patches from patches/, swaps in
# the wasm backends, cross-compiles libunbound with the wasi-sdk, and links
# the reactor module.
#
# It expects WASI_SDK to point at a wasi-sdk installation. It normally runs
# inside the pinned container (see Dockerfile.build and `make module`), but
# works on any host with the same tools (`make module-local`).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

value() { awk -v key="$1" '$1==key {print $3}' "$ROOT/versions.mk"; }
UNBOUND_VERSION=$(value UNBOUND_VERSION)
UNBOUND_SHA256=$(value UNBOUND_SHA256)

: "${WASI_SDK:?set WASI_SDK to the wasi-sdk directory}"
WORK=${WORK:-$ROOT/build/work}
DL=$ROOT/build/downloads
SRC=$WORK/unbound-$UNBOUND_VERSION
STUB=$WORK/stub
OUT=${OUT:-$WORK/unbound.wasm}
mkdir -p "$DL" "$WORK" "$STUB/include" "$STUB/lib"

# Download the pinned upstream release, verify it, and extract a fresh
# tree, so every build starts from pristine sources plus patches/.
TARBALL=$DL/unbound-$UNBOUND_VERSION.tar.gz
if [ ! -f "$TARBALL" ]; then
	curl -fL --retry 3 -o "$TARBALL" \
		"https://nlnetlabs.nl/downloads/unbound/unbound-$UNBOUND_VERSION.tar.gz"
fi
echo "$UNBOUND_SHA256  $TARBALL" | sha256sum -c -
rm -rf "$SRC"
mkdir -p "$SRC"
tar -xzf "$TARBALL" -C "$SRC" --strip-components=1

for p in "$ROOT"/patches/*.patch; do
	patch -d "$SRC" -p1 --fuzz=0 --silent < "$p"
done

# configure insists on libexpat (used only by unbound-anchor, which is not
# built); satisfy it with a header stub and an empty lib directory.
cat > "$STUB/include/expat.h" <<'EOT'
typedef void* XML_Parser; enum XML_Status { XML_STATUS_ERROR=0, XML_STATUS_OK=1, XML_STATUS_SUSPENDED=2 }; enum XML_Status XML_StopParser(XML_Parser, int);
EOT

# The crypto seams: configure normally hard-fails without an SSL library,
# and val_sigcrypt.c hard-fails without a known crypto backend. Redirect
# both to HAVE_HOSTCALL_CRYPTO, the host-provided crypto in
# backends/secalgo.c. The needles are exact so an upstream change fails the
# build loudly instead of silently building something else.
python3 - "$SRC/configure" <<'PY'
import pathlib
import sys

src = pathlib.Path(sys.argv[1]).parent

configure = src / "configure"
text = configure.read_text()
needle = 'as_fn_error $? "Need SSL library to do digital signature cryptography" "$LINENO" 5'
if needle not in text:
    raise SystemExit("configure crypto seam changed")
configure.write_text(text.replace(
    needle, 'printf "%s\\n" "#define HAVE_HOSTCALL_CRYPTO 1" >>confdefs.h'))

sigcrypt = src / "validator/val_sigcrypt.c"
text = sigcrypt.read_text()
needle = "#if !defined(HAVE_SSL) && !defined(HAVE_NSS) && !defined(HAVE_NETTLE)"
if needle not in text:
    raise SystemExit("val_sigcrypt crypto seam changed")
sigcrypt.write_text(text.replace(
    needle, needle + " && !defined(HAVE_HOSTCALL_CRYPTO)", 1))
PY

# Replace whole upstream files with the wasm backends: randomness and
# DNSSEC crypto go through host imports (see backends/README.md).
cp "$ROOT/backends/random.c" "$SRC/util/random.c"
cp "$ROOT/backends/secalgo.c" "$SRC/validator/val_secalgo.c"

# Cross-compiling means configure cannot run test programs; config.cache
# supplies the answers for the wasm32-wasi target.
cp "$ROOT/build/config.cache" "$WORK/config.cache"

FLAGS=$(tr '\n' ' ' < "$ROOT/build/configure.flags")
# -ffile-prefix-map keeps the build directory out of the binary for
# reproducibility; -include injects the socket remapping into every
# translation unit; _WASI_EMULATED_SIGNAL is required by wasi-libc's
# signal.h, which Unbound includes but never meaningfully uses.
CFLAGS="-O2 -Werror=date-time -DHAVE_HOSTCALL_CRYPTO -D_WASI_EMULATED_SIGNAL -ffile-prefix-map=$SRC=. -include $ROOT/backends/sockets_remap.h -I$ROOT -I$ROOT/backends"

(
	cd "$SRC"

	CC="$WASI_SDK/bin/clang" AR="$WASI_SDK/bin/llvm-ar" RANLIB="$WASI_SDK/bin/llvm-ranlib" \
	CFLAGS="$CFLAGS" LDFLAGS='-Wl,--allow-undefined' \
	./configure --cache-file="$WORK/config.cache" --with-libexpat="$STUB" $FLAGS

	# Post-configure fixups that have no configure-time knobs.
	#
	# config.h: getaddrinfo and struct addrinfo come from backends/netdb.h,
	# which configure cannot detect (wasi-libc has no netdb.h); fsync
	# exists in wasi-libc; sendmsg, recvmsg, and unix sockets are declared
	# absent so Unbound uses the sendto/recvfrom paths the ABI supports.
	#
	# Makefile: drop the compat objects that either duplicate wasi-libc
	# and backend functions (getaddrinfo compat, arc4random and entropy,
	# sha512) or fail to build on wasm.
	python3 - <<'PY'
from pathlib import Path

config = Path("config.h")
text = config.read_text()
for old, new in [
    ("/* #undef HAVE_GETADDRINFO */", "#define HAVE_GETADDRINFO 1"),
    ("/* #undef HAVE_STRUCT_ADDRINFO */", "#define HAVE_STRUCT_ADDRINFO 1"),
    ("/* #undef HAVE_FSYNC */", "#define HAVE_FSYNC 1"),
    ("#define HAVE_SENDMSG 1", "/* #undef HAVE_SENDMSG */"),
    ("#define HAVE_RECVMSG 1", "/* #undef HAVE_RECVMSG */"),
    ("#define HAVE_SYS_UN_H 1", "/* #undef HAVE_SYS_UN_H */"),
]:
    text = text.replace(old, new)
config.write_text(text)

makefile = Path("Makefile")
text = makefile.read_text()
for obj in ["fake-rfc2553", "arc4random", "arc4random_uniform", "arc4_lock",
            "getentropy_linux", "sha512"]:
    for form in ["${LIBOBJDIR}" + obj + "$U.o", obj + ".o", obj + ".lo"]:
        text = text.replace(form + " ", "").replace(" " + form, "")
makefile.write_text(text)
PY

	make -j"${JOBS:-4}" CFLAGS="$CFLAGS" libunbound.la

	# Compile the standalone backends and link the reactor module.
	# --allow-undefined leaves the unbound_wasm host imports unresolved
	# for the wazero runtime to satisfy at instantiation.
	for f in guest event sockets compat; do
		"$WASI_SDK/bin/clang" -O2 -DHAVE_HOSTCALL_CRYPTO -D_WASI_EMULATED_SIGNAL \
			-I. -I"$ROOT" -I"$ROOT/backends" \
			-c "$ROOT/backends/$f.c" -o "$WORK/$f.o"
	done
	"$WASI_SDK/bin/clang" -O2 -mexec-model=reactor \
		-Wl,--allow-undefined -Wl,--gc-sections -Wl,--strip-all \
		-Wl,-z,stack-size=2097152 \
		-o "$OUT" \
		"$WORK/guest.o" "$WORK/event.o" "$WORK/sockets.o" "$WORK/compat.o" \
		.libs/libunbound.a -lwasi-emulated-signal
)

sha256sum "$OUT"

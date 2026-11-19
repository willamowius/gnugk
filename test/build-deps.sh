#!/bin/bash
# Build the latest PTLib and H323Plus from the willamowius GitHub repos,
# then GnuGk and the test endpoint against them.
#
# usage: test/build-deps.sh [deps-dir]
#   deps-dir defaults to $GKTEST_DEPS or ~/gnugk-test-deps
#
# The libraries are always updated to the latest commit of their default branch (GitHub HEAD) before building,
# then the patches in test/patches/<repo>/ are applied (fixes not upstream yet; skipped once upstream has them).
# A library is only rebuilt when its commit, its patches, its configure options or the compiler changed since its
# last successful build (H323Plus also when PTLib was rebuilt); GKTEST_REBUILD=1 always rebuilds them.
set -euo pipefail
# set -e ends the script without a word when a command outside run() fails, say where
trap 'echo "FAILED: build-deps.sh line $LINENO: $BASH_COMMAND" >&2' ERR

GK_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${1:-${GKTEST_DEPS:-$HOME/gnugk-test-deps}}"
JOBS="${JOBS:-$(nproc)}"
mkdir -p "$DEPS"
LOGS="$DEPS/logs"
mkdir -p "$LOGS"

# fetch the remote's HEAD (its default branch on GitHub) without touching the checkout, print the commit
fetch_repo() {
	local name="$1" url="$2"
	if [ -d "$DEPS/$name/.git" ]; then
		echo "== updating $name" >&2
		git -C "$DEPS/$name" fetch -q --depth 1 "$url" HEAD
		git -C "$DEPS/$name" rev-parse FETCH_HEAD
	else
		echo "== cloning $name" >&2
		git clone -q --depth 1 "$url" "$DEPS/$name"
		git -C "$DEPS/$name" rev-parse HEAD
	fi
}

# check out a fetched commit, dropping the patches and the files configure wrote (some are tracked in git)
checkout_repo() {
	local name="$1" commit="$2"
	git -C "$DEPS/$name" reset -q --hard "$commit"
}

show_commit() {
	echo "   $1 at $(git -C "$DEPS/$1" log -1 --format='%h %ad' --date=short "$2")"
}

# apply test/patches/<name>/*.patch on top of the GitHub checkout
apply_patches() {
	local name="$1" patch
	for patch in "$GK_DIR/test/patches/$name"/*.patch; do
		[ -e "$patch" ] || continue
		if git -C "$DEPS/$name" apply --check "$patch" 2>/dev/null; then
			git -C "$DEPS/$name" apply "$patch"
			echo "   applied $(basename "$patch")"
		elif git -C "$DEPS/$name" apply --reverse --check "$patch" 2>/dev/null; then
			echo "   $(basename "$patch") is already in $name, remove it from test/patches/$name"
		else
			echo "FAILED: $(basename "$patch") doesn't apply to $name any more" >&2
			exit 1
		fi
	done
}

# what goes into a library build: commit, patches, configure options, compiler (and whatever else is passed)
build_key() {
	local name="$1" commit="$2"; shift 2
	{
		echo "$commit"
		cat "$GK_DIR/test/patches/$name"/*.patch 2>/dev/null || true
		echo "$*"
		${CXX:-c++} -dumpfullversion 2>/dev/null || ${CXX:-c++} -dumpversion 2>/dev/null || true
	} | sha256sum | cut -d' ' -f1
}

# true if the library was built with this key and is still there
up_to_date() {
	local name="$1" key="$2" lib="$3"
	[ -z "${GKTEST_REBUILD:-}" ] && [ -f "$DEPS/$name.build-key" ] \
		&& [ "$(cat "$DEPS/$name.build-key")" = "$key" ] && compgen -G "$lib" > /dev/null
}

run() {
	local log="$1"; shift
	if ! "$@" > "$LOGS/$log" 2>&1; then
		echo "FAILED: $* (see $LOGS/$log)" >&2
		tail -20 "$LOGS/$log" >&2
		exit 1
	fi
}

PTLIB_COMMIT="$(fetch_repo ptlib https://github.com/willamowius/ptlib.git)"
show_commit ptlib "$PTLIB_COMMIT"
H323PLUS_COMMIT="$(fetch_repo h323plus https://github.com/willamowius/h323plus.git)"
show_commit h323plus "$H323PLUS_COMMIT"

export PTLIBDIR="$DEPS/ptlib"
export OPENH323DIR="$DEPS/h323plus"

# when the key is unchanged the checkout (patched and configured) is left alone
PTLIB_OPTS=(--enable-ipv6 --disable-sdl --disable-odbc --disable-lua)
PTLIB_KEY="$(build_key ptlib "$PTLIB_COMMIT" "${PTLIB_OPTS[@]}")"
if up_to_date ptlib "$PTLIB_KEY" "$PTLIBDIR/lib_*/libpt_s.a"; then
	echo "== PTLib unchanged, not rebuilt"
else
	rm -f "$DEPS/ptlib.build-key"
	checkout_repo ptlib "$PTLIB_COMMIT"
	apply_patches ptlib
	echo "== building PTLib"
	cd "$PTLIBDIR"
	run ptlib-configure.log ./configure "${PTLIB_OPTS[@]}"
	run ptlib-make.log make -j"$JOBS" optnoshared
	echo "$PTLIB_KEY" > "$DEPS/ptlib.build-key"
fi

# same options as the GnuGk manual: H.235 is needed for GnuGk to verify H.235.1 tokens
H323PLUS_OPTS=(--enable-h235 --enable-h46017 --enable-h46026)
H323PLUS_KEY="$(build_key h323plus "$H323PLUS_COMMIT" "${H323PLUS_OPTS[@]}" "ptlib=$PTLIB_KEY")"
if up_to_date h323plus "$H323PLUS_KEY" "$OPENH323DIR/lib/libh323_*_s.a"; then
	echo "== H323Plus unchanged, not rebuilt"
else
	rm -f "$DEPS/h323plus.build-key"
	checkout_repo h323plus "$H323PLUS_COMMIT"
	apply_patches h323plus
	echo "== building H323Plus"
	cd "$OPENH323DIR"
	run h323plus-configure.log ./configure "${H323PLUS_OPTS[@]}"
	rm -rf "$OPENH323DIR"/lib/obj_*	# make doesn't notice changed configure options
	run h323plus-make.log make -j"$JOBS" optnoshared
	echo "$H323PLUS_KEY" > "$DEPS/h323plus.build-key"
fi

echo "== building GnuGk"
cd "$GK_DIR"
# Lua (for test_scripting.py): GnuGk's configure links -llua, Debian/Ubuntu only ship liblua5.x.so and keep the
# headers in /usr/include/lua5.x, so point configure at them (no Lua headers: the Lua tests fail with a clear message)
LUA_OPTS=()
for v in 5.4 5.3; do
	if [ -f "/usr/include/lua$v/lua.h" ]; then
		LUA_OPTS+=("--with-lua-include-dir=/usr/include/lua$v")
		# (no ls | head here: with pipefail a missing path would end the script)
		lib=""
		for f in /usr/lib/*/liblua$v.so /usr/lib/liblua$v.so; do
			if [ -e "$f" ]; then
				lib="$f"
				break
			fi
		done
		if [ -n "$lib" ]; then
			mkdir -p "$DEPS/lua-lib"
			ln -sf "$lib" "$DEPS/lua-lib/liblua.so"
			LUA_OPTS+=("--with-lua-lib-dir=$DEPS/lua-lib")
		fi
		break
	fi
done
run gnugk-configure.log ./configure --enable-h46018 --enable-large-fdset "${LUA_OPTS[@]}"
# always build from scratch: make doesn't notice when configure changes the compiler flags
rm -rf "$GK_DIR"/obj_*_s
run gnugk-make.log make -j"$JOBS" optnoshared

echo "== building test endpoint"
rm -rf "$GK_DIR"/addpasswd/obj_*_s "$GK_DIR"/test/endpoint/obj_*_s
run addpasswd-make.log make -C "$GK_DIR/addpasswd" -j"$JOBS" optnoshared
run endpoint-make.log make -C "$GK_DIR/test/endpoint" -j"$JOBS" optnoshared

echo "== done"
echo "export PTLIBDIR=$PTLIBDIR OPENH323DIR=$OPENH323DIR"

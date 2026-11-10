#!/bin/bash
# Build the latest PTLib and H323Plus from the willamowius GitHub repos,
# then GnuGk and the test endpoint against them.
#
# usage: test/build-deps.sh [deps-dir]
#   deps-dir defaults to $GKTEST_DEPS or ~/gnugk-test-deps
#
# The libraries are always updated to the latest commit of their default branch (GitHub HEAD) before building,
# then the patches in test/patches/<repo>/ are applied (fixes not upstream yet; skipped once upstream has them).
set -euo pipefail
# set -e ends the script without a word when a command outside run() fails, say where
trap 'echo "FAILED: build-deps.sh line $LINENO: $BASH_COMMAND" >&2' ERR

GK_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${1:-${GKTEST_DEPS:-$HOME/gnugk-test-deps}}"
JOBS="${JOBS:-$(nproc)}"
mkdir -p "$DEPS"
LOGS="$DEPS/logs"
mkdir -p "$LOGS"

update_repo() {
	local name="$1" url="$2"
	if [ -d "$DEPS/$name/.git" ]; then
		echo "== updating $name"
		# the remote's HEAD: its default branch on GitHub
		git -C "$DEPS/$name" fetch -q --depth 1 "$url" HEAD
		git -C "$DEPS/$name" reset -q --hard FETCH_HEAD
	else
		echo "== cloning $name"
		git clone -q --depth 1 "$url" "$DEPS/$name"
	fi
	echo "   $name at $(git -C "$DEPS/$name" log -1 --format='%h %ad' --date=short)"
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

run() {
	local log="$1"; shift
	if ! "$@" > "$LOGS/$log" 2>&1; then
		echo "FAILED: $* (see $LOGS/$log)" >&2
		tail -20 "$LOGS/$log" >&2
		exit 1
	fi
}

update_repo ptlib https://github.com/willamowius/ptlib.git
apply_patches ptlib
update_repo h323plus https://github.com/willamowius/h323plus.git
apply_patches h323plus

export PTLIBDIR="$DEPS/ptlib"
export OPENH323DIR="$DEPS/h323plus"

echo "== building PTLib"
cd "$PTLIBDIR"
run ptlib-configure.log ./configure --enable-ipv6 --disable-sdl --disable-odbc --disable-lua
run ptlib-make.log make -j"$JOBS" optnoshared

echo "== building H323Plus"
cd "$OPENH323DIR"
# same options as the GnuGk manual: H.235 is needed for GnuGk to verify H.235.1 tokens
run h323plus-configure.log ./configure --enable-h235 --enable-h46017 --enable-h46026
rm -rf "$OPENH323DIR"/lib/obj_*	# make doesn't notice changed configure options
run h323plus-make.log make -j"$JOBS" optnoshared

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

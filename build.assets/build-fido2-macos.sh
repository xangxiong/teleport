#!/bin/bash
#
# Builds libfido2 and dependencies, caching the resulting binaries in the local
# filesystem.
#
# Run `build-fido2-macos.sh build` to build libfido2 and its dependencies, at
# the versions specified in the script.
# Run `build-fido2-macos.sh pkg_config_path` to print the path to the
# prior-built libfido2-static.pc file.
#
# Written mainly for macOS builders.
set -eu

readonly MACOS_VERSION_MIN=10.13

# Note: versions are the same as the corresponding git tags for each repo.
readonly CBOR_VERSION=v0.9.0
readonly CRYPTO_VERSION=OpenSSL_1_1_1q
readonly FIDO2_VERSION=1.11.0

readonly LIB_CACHE="/tmp/teleport-fido2-cache"
readonly PKGFILE_DIR="$LIB_CACHE/fido2-${FIDO2_VERSION}_cbor-${CBOR_VERSION}_crypto-${CRYPTO_VERSION}"

# Library cache paths, implicitly matched by fetch_and_build.
readonly CBOR_PATH="$LIB_CACHE/cbor-$CBOR_VERSION"
readonly CRYPTO_PATH="$LIB_CACHE/crypto-$CRYPTO_VERSION"
readonly FIDO2_PATH="$LIB_CACHE/fido2-$FIDO2_VERSION"

fetch_and_build() {
  local name="$1"      # eg, cbor
  local version="$2"   # eg, v0.9.0
  local url="$3"       # eg, https://github.com/...
  local buildcmd="$4"  # eg, cbor_build, a bash function name
  echo "$name: fetch and build" >&2

  mkdir -p "$LIB_CACHE"
  local tmp=''
  tmp="$(mktemp -d "$LIB_CACHE/build.XXXXXX")"
  # Early expansion on purpose.
  #shellcheck disable=SC2064
  trap "rm -fr '$tmp'" EXIT

  local fullname="$name-$version"
  local install_path="$tmp/$fullname"

  cd "$tmp"
  git clone --depth=1 -b "$version" "$url"
  cd "$(ls)"  # a single folder exists at this point
  mkdir -p "$install_path"
  eval "$buildcmd '$PWD' '$install_path'"

  # Fix path in pkgconfig files.
  local dest="$LIB_CACHE/$fullname"
  find "$install_path" \
    -name '*.pc' \
    -exec sed -i '' "s@$install_path@$dest@g" {} +

  # Check if another builder beat us. Builds _should_ be equivalent.
  if [[ ! -d "$dest" ]]; then
    echo "$name: moving $fullname to $dest" >&2
    mv "$install_path" "$dest"
  fi
}

cbor_build() {
  local src="$1"
  local dest="$2"
  echo 'cbor: building' >&2
  cd "$src"

  cmake \
    -DCBOR_CUSTOM_ALLOC=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$dest" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$MACOS_VERSION_MIN" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DWITH_EXAMPLES=OFF \
    -G "Unix Makefiles" \
    .
  make
  make install
}

cbor_fetch_and_build() {
  fetch_and_build \
    cbor "$CBOR_VERSION" 'https://github.com/pjk/libcbor.git' cbor_build
}

crypto_build() {
  local src="$1"
  local dest="$2"
  echo 'crypto: building' >&2
  cd "$src"

  ./config \
    -mmacosx-version-min="$MACOS_VERSION_MIN" \
    --prefix="$dest" \
    --openssldir="$dest/openssl@1.1" \
    no-shared \
    no-zlib
  # Build and copy only what we need instead of 'make && make install'.
  # It's a bit quicker.
  make build_generated libcrypto.a libcrypto.pc
  mkdir -p "$dest/"{include,lib/pkgconfig}
  cp -r include/openssl "$dest/include/"
  cp libcrypto.a "$dest/lib/"
  cp libcrypto.pc "$dest/lib/pkgconfig"
}

crypto_fetch_and_build() {
  fetch_and_build \
    crypto "$CRYPTO_VERSION" 'https://github.com/openssl/openssl.git' \
    crypto_build
}

fido2_build() {
  local src="$1"
  local dest="$2"
  echo 'fido2: building' >&2
  cd "$src"

  export PKG_CONFIG_PATH="$LIB_CACHE/cbor-$CBOR_VERSION/lib/pkgconfig:$LIB_CACHE/crypto-$CRYPTO_VERSION/lib/pkgconfig"
  cmake \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_MANPAGES=OFF \
    -DBUILD_TOOLS=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$dest" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$MACOS_VERSION_MIN" \
    -G "Unix Makefiles" \
    .
  make
  make install
}

fido2_fetch_and_build() {
  fetch_and_build \
    fido2 "$FIDO2_VERSION" 'https://github.com/Yubico/libfido2.git' fido2_build
}

fido2_compile_toy() {
  local toydir=''
  toydir="$(mktemp -d)"
  # Early expansion on purpose.
  #shellcheck disable=SC2064
  trap "rm -fr '$toydir'" EXIT

  cat >"$toydir/toy.c" <<EOF
#include <fido.h>

int main() {
  fido_init(0 /* flags */);
  return 0;
}
EOF

  export PKG_CONFIG_PATH="$PKGFILE_DIR"
  # Word splitting desired for pkg-config.
  #shellcheck disable=SC2046
  gcc \
    $(pkg-config --cflags --libs libfido2-static) \
    -o "$toydir/toy.bin" \
    "$toydir/toy.c"
}

usage() {
  echo "Usage: $0 build|pkg_config_path" >&2
}

build() {
  if [[ ! -d "$CBOR_PATH" ]]; then
    cbor_fetch_and_build
  fi

  if [[ ! -d "$CRYPTO_PATH" ]]; then
    crypto_fetch_and_build
  fi

  if [[ ! -d "$FIDO2_PATH" ]]; then
    fido2_fetch_and_build
  fi

  local pkgfile="$PKGFILE_DIR/libfido2-static.pc"
  if [[ ! -f "$pkgfile" ]]; then
    local tmp=''
    tmp="$(mktemp)"  # file, not dir!
    # Early expansion on purpose.
    #shellcheck disable=SC2064
    trap "rm -f '$tmp'" EXIT

    # Write libfido2-static.pc to tmp.
    cat >"$tmp" <<EOF
prefix=$FIDO2_PATH
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: libfido2
Description: A FIDO2 library
URL: https://github.com/yubico/libfido2
Version: $FIDO2_VERSION
Libs: -framework CoreFoundation -framework IOKit \${libdir}/libfido2.a $CBOR_PATH/lib/libcbor.a $CRYPTO_PATH/lib/libcrypto.a
Cflags: -I\${includedir} -I$CBOR_PATH/include -I$CRYPTO_PATH/include -mmacosx-version-min="$MACOS_VERSION_MIN"
EOF

    # Move .pc file to expected path.
    mkdir -p "$PKGFILE_DIR"
    if [[ ! -f "$pkgfile" ]]; then
      echo "fido2: creating $pkgfile" >&2
      mv "$tmp" "$pkgfile"
    fi
  fi
}

main() {
  if [[ $# -ne 1 ]]; then
    usage
    exit 1
  fi

  case "$1" in
    build)
      build
      if ! fido2_compile_toy; then
        echo 'Failed to compile fido2 test program, cleaning cache and retrying' >&2
        rm -fr "$CBOR_PATH" "$CRYPTO_PATH" "$FIDO2_PATH"
        build
      fi
      ;;
    pkg_config_path)
      echo "$PKGFILE_DIR"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"

#!/usr/bin/env bash
# 用 Android NDK 交叉编译静态 arm64 tcpdump + libpcap
# 用法：在 CI 中已安装 NDK 且设置了 $ANDROID_HOME 后执行本脚本。
# 产物输出到 $PWD/build_native/tcpdump
set -euo pipefail

NDK_VERSION="${NDK_VERSION:-26.1.10909125}"
LIBPCAP_VERSION="${LIBPCAP_VERSION:-1.10.4}"
TCPDUMP_VERSION="${TCPDUMP_VERSION:-4.99.4}"
API="${API:-24}"
PREFIX="aarch64-linux-android"

: "${ANDROID_HOME:?请先设置 ANDROID_HOME}"
TOOLCHAIN="$ANDROID_HOME/ndk/$NDK_VERSION/toolchains/llvm/prebuilt/linux-x86_64/bin"
[ -x "$TOOLCHAIN/$PREFIX$API-clang" ] || { echo "找不到 NDK 工具链: $TOOLCHAIN"; exit 1; }

CC="$TOOLCHAIN/$PREFIX$API-clang"
AR="$TOOLCHAIN/llvm-ar"
RANLIB="$TOOLCHAIN/llvm-ranlib"
NM="$TOOLCHAIN/llvm-nm"
STRIP="$TOOLCHAIN/llvm-strip"

WORK="$(pwd)/build_native"
mkdir -p "$WORK"
cd "$WORK"

echo "== 下载 libpcap-$LIBPCAP_VERSION =="
curl -fsSL -o libpcap.tar.gz "https://www.tcpdump.org/release/libpcap-$LIBPCAP_VERSION.tar.gz"
echo "== 下载 tcpdump-$TCPDUMP_VERSION =="
curl -fsSL -o tcpdump.tar.gz "https://www.tcpdump.org/release/tcpdump-$TCPDUMP_VERSION.tar.gz"

echo "== 编译 libpcap =="
rm -rf "libpcap-$LIBPCAP_VERSION"
tar xzf libpcap.tar.gz
cd "libpcap-$LIBPCAP_VERSION"
CC="$CC" AR="$AR" RANLIB="$RANLIB" NM="$NM" \
  CFLAGS="-Os -fPIE" \
  ./configure --host="$PREFIX" --with-pcap=linux --without-libnl \
    --disable-shared --enable-static ac_cv_linux_vers=2 >/dev/null
make -j"$(nproc)" >/dev/null
cd "$WORK"

echo "== 编译 tcpdump =="
rm -rf "tcpdump-$TCPDUMP_VERSION"
tar xzf tcpdump.tar.gz
cd "tcpdump-$TCPDUMP_VERSION"
CC="$CC" \
  CPPFLAGS="-I$WORK/libpcap-$LIBPCAP_VERSION" \
  LDFLAGS="-L$WORK/libpcap-$LIBPCAP_VERSION" \
  LIBS="-lpcap" \
  CFLAGS="-Os -fPIE -D_GNU_SOURCE" \
  ./configure --host="$PREFIX" --without-crypto \
    ac_cv_func_getservent=yes >/dev/null
# Android(bionic) 交叉编译时 configure 检测不到这些，需补上：
#  - HAVE_GETSERVENT：否则会 include 本地 getservent.h 与 bionic 的 netdb.h 冲突
#  - HAVE_FCNTL_H   ：否则不会 #include <fcntl.h>，导致 open() 未声明
# 先删旧行再在末尾追加，确保最终生效（config.h 里可能是注释或裸 #undef 两种格式）
sed -i '/^.*HAVE_GETSERVENT/d' config.h
sed -i '/^.*HAVE_FCNTL_H/d' config.h
echo '#define HAVE_GETSERVENT 1' >> config.h
echo '#define HAVE_FCNTL_H 1' >> config.h
make -j"$(nproc)" tcpdump
cd "$WORK"

cp "tcpdump-$TCPDUMP_VERSION/tcpdump" "$WORK/tcpdump"
"$STRIP" "$WORK/tcpdump"
echo "BUILT: $WORK/tcpdump"
"$WORK/tcpdump" --version 2>&1 | head -2 || true
ls -la "$WORK/tcpdump"
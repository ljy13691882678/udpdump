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
# 源码级修复(不依赖 config.h，避免 make 重新生成覆盖)：
# 1) bionic 的 netdb.h 已声明 getservent，删除本地 getservent.h 里的冲突 #error 块
sed -i '/^#ifdef _NETDB_H_$/,/^#endif$/d' getservent.h
# 2) 强制包含 <fcntl.h>，让 open() 有声明(由下面 CFLAGS 的 -include 完成)
CC="$CC" \
  CPPFLAGS="-I$WORK/libpcap-$LIBPCAP_VERSION" \
  LDFLAGS="-L$WORK/libpcap-$LIBPCAP_VERSION" \
  LIBS="-lpcap" \
  CFLAGS="-Os -fPIE -D_GNU_SOURCE -include fcntl.h" \
  ./configure --host="$PREFIX" --without-crypto \
    ac_cv_func_getservent=yes >/dev/null
make -j"$(nproc)" tcpdump
cd "$WORK"

cp "tcpdump-$TCPDUMP_VERSION/tcpdump" "$WORK/tcpdump"
"$STRIP" "$WORK/tcpdump"
echo "BUILT: $WORK/tcpdump"
"$WORK/tcpdump" --version 2>&1 | head -2 || true
ls -la "$WORK/tcpdump"
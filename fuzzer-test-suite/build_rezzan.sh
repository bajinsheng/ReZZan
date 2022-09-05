#!/bin/bash -e

# Examples
# ASAN:
# AFL_USE_ASAN=1 ./build_rezzan.sh openssl-1.0.1f
# ReZZan:
# AFL_CHECK_REZZAN=1 ./build_rezzan.sh openssl-1.0.1f
# ReZZan_lite:
# REZZAN_NONCE_SIZE=64 AFL_CHECK_REZZAN=1 ./build_rezzan.sh openssl-1.0.1f

PKG=$1
DIR=`pwd`

export FUZZING_ENGINE="afl"
export CC=${DIR}/../AFL/afl-clang-fast
export CXX=${DIR}/../AFL/afl-clang-fast++
export CFLAGS="-g -O2 -fno-omit-frame-pointer"
export CXXFLAGS="-g -O2 -fno-omit-frame-pointer -lpthread -ldl"
export LIBS="-lstdc++ -lpthread -ldl"
export AFL_SRC=${DIR}/../AFL
export LIBFUZZER_SRC=${DIR}/llvm

mkdir -p ${DIR}/${PKG}/build
cd ${DIR}/${PKG}/build

if [ -f ${DIR}/$PKG/build.sh ]; then
  ${DIR}/$PKG/build.sh
  echo "$PKG build done"
else
  echo "$PKG is not a package path"
fi
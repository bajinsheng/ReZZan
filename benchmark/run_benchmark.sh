#!/bin/bash -e

path=`readlink -f ${BASH_SOURCE:-$0}`
DIR=`dirname $path`
AFL_FUZZ=${DIR}/../AFL/afl-fuzz

export CC=${DIR}/../AFL/afl-clang-fast
export CXX=${DIR}/../AFL/afl-clang-fast++
export ASAN_OPTIONS=detect_leaks=0

if [ $# -lt 2 ]; then
    echo "Usage: $0 <fuzzer> <target>"
    echo "fuzzer: {asan, rezzan, rezzan_lite, native}"
    echo "target: {cxxfilt, file, jerryscript, mupdf, nm, objdump, libpng, size, sqlite, tcpdump}"
    exit 1
fi

fuzzer=$1
target=$2

if [ $fuzzer == "asan" ]; then
    export AFL_USE_ASAN=1 
elif [ $fuzzer == "rezzan" ]; then
    export AFL_CHECK_REZZAN=1
elif [ $fuzzer == "rezzan_lite" ]; then
    export AFL_CHECK_REZZAN=1
    export REZZAN_NONCE_SIZE=64
elif [ $fuzzer == "native" ]; then
    true
else
    echo "Unknown fuzzer"
    echo "Please select one from {asan, rezzan, rezzan_lite}"
    exit 1
fi

if [ $target == "cxxfilt" ]; then
    cd binutils-2.31.90
    ./configure
    make clean all
    cd ..
    unset ASAN_OPTIONS
    timeout 24h ${AFL_FUZZ} -m none -t 1000 -i in/${target}/ -o /tmp/${target}_${fuzzer} -- ./binutils-2.31.90/binutils/cxxfilt
elif [ $target == "file" ]; then
    cd file
    autoreconf -i &>/dev/null || true
    autoreconf -i
    ./configure --disable-shared --disable-libseccomp --enable-static
    make clean all
    cd ../
    unset ASAN_OPTIONS
    timeout 24h ${AFL_FUZZ} -m none -t 1000 -i in/${target}/ -o /tmp/${target}_${fuzzer} -- ./file/src/file -m ./config/magic.mgc @@
elif [ $target == "jerryscript" ]; then
    cd jerryscript
    python3 ./tools/build.py --clean --debug --lto=off
    cd ..
    unset ASAN_OPTIONS
    timeout 24h ${AFL_FUZZ} -m none -t 1000 -i in/${target}/ -o /tmp/${target}_${fuzzer} -- ./jerryscript/build/bin/jerry @@
elif [ $target == "mupdf" ]; then
    cd mupdf-1.19.0-source
    make HAVE_X11=no HAVE_GLUT=no clean all
    cd ../
    unset ASAN_OPTIONS
    timeout 24h ${AFL_FUZZ} -m none -t 1000 -i in/${target}/ -o /tmp/${target}_${fuzzer} -- ./mupdf-1.19.0-source/build/release/mutool show @@
elif [ $target == "nm" ]; then
    cd binutils-2.31.90
    ./configure
    make clean all
    cd ..
    unset ASAN_OPTIONS
    timeout 24h ${AFL_FUZZ} -m none -t 1000 -i in/${target}/ -o /tmp/${target}_${fuzzer} -- ./binutils-2.31.90/binutils/nm-new @@
elif [ $target == "objdump" ]; then
    cd binutils-2.31.90
    ./configure
    make clean all
    cd ..
    unset ASAN_OPTIONS
    timeout 24h ${AFL_FUZZ} -m none -t 1000 -i in/${target}/ -o /tmp/${target}_${fuzzer} -- ./binutils-2.31.90/binutils/objdump -a @@
elif [ $target == "libpng" ]; then
    cd libpng
    ./configure --disable-shared --disable-libseccomp
    make clean all
    cd ../
    unset ASAN_OPTIONS
    timeout 24h ${AFL_FUZZ} -m none -t 1000 -i in/${target}/ -o /tmp/${target}_${fuzzer} -- ./libpng/pngfix @@
elif [ $target == "size" ]; then
    cd binutils-2.31.90
    ./configure
    make clean all
    cd ..
    unset ASAN_OPTIONS
    timeout 24h ${AFL_FUZZ} -m none -t 1000 -i in/${target}/ -o /tmp/${target}_${fuzzer} -- ./binutils-2.31.90/binutils/size @@
elif [ $target == "sqlite" ]; then
    cd sqlite
    ./configure --disable-shared
    make clean all
    cd ../
    unset ASAN_OPTIONS
    timeout 24h ${AFL_FUZZ} -m none -t 1000 -i in/${target}/ -o /tmp/${target}_${fuzzer} -- ./sqlite/sqlite3
elif [ $target == "tcpdump" ]; then
    cd libpcap
    autoreconf -f -i
    ./configure --disable-shared
    make clean all
    cd ../tcpdump
    autoreconf -f -i
    ./configure
    make clean all
    cd ..
    unset ASAN_OPTIONS
    timeout 24h ${AFL_FUZZ} -m none -t 1000 -i in/${target}/ -o /tmp/${target}_${fuzzer} -- ./tcpdump/tcpdump -n -e -r @@
else
    echo "Unknown target"
    echo "Please select one from {cxxfilt, file, jerryscript, mupdf, nm, objdump, libpng, size, sqlite, tcpdump}"
    exit 1
fi








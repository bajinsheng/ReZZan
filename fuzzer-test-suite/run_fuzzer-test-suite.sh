#!/bin/bash -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <fuzzer> <target>"
    echo "fuzzer: {asan, rezzan, rezzan_lite}"
    echo "target: {c-ares-CVE-2016-5180, json-2017-02-12, libxml2-v2.9.2, openssl-1.0.1f, pcre2-10.00}"
    exit 1
fi

export ASAN_OPTIONS=detect_leaks=0

fuzzer=$1
target=$2

if [ $fuzzer == "asan" ]; then
    export AFL_USE_ASAN=1 
elif [ $fuzzer == "rezzan" ]; then
    export AFL_CHECK_REZZAN=1
elif [ $fuzzer == "rezzan_lite" ]; then
    export AFL_CHECK_REZZAN=1
    export REZZAN_NONCE_SIZE=64
else
    echo "Unknown fuzzer"
    echo "Please select one from {asan, rezzan, rezzan_lite}"
    exit 1
fi

if [ $target != "c-ares-CVE-2016-5180" ] && \
    [ $target != "json-2017-02-12" ] && \
    [ $target != "libxml2-v2.9.2" ] && \
    [ $target != "openssl-1.0.1f" ] && \
    [ $target != "pcre2-10.00" ]; then
    echo "Unknown target"
    echo "Please select one from {c-ares-CVE-2016-5180, json-2017-02-12, libxml2-v2.9.2, openssl-1.0.1f, pcre2-10.00}"
    exit 1
fi

./build_rezzan.sh $target
unset ASAN_OPTIONS

cd $target
AFL_BENCH_UNTIL_CRASH=1 timeout 24h /AFL/afl-fuzz -m none -t 1000 -i seeds -o /tmp/${target}_${fuzzer} -- ./build/${target}-afl @@

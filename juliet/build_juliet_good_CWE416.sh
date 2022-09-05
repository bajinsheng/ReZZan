#!/bin/bash

path=`readlink -f ${BASH_SOURCE:-$0}`
DIR=`dirname $path`
CWE=$1
TARGET_DIR=C/testcases/${CWE}

export REZZAN_PRINTF=1
export ASAN_OPTIONS=detect_leaks=0

cd ${TARGET_DIR}
pwd
echo "target,Asan,ReZZan,ReZZan_lite" > ${DIR}/results/${CWE}_good.csv
rm -rf *.asan
rm -rf *.rezzan
rm -rf *.lite

# Build
make clean > /dev/null
make CC=clang CPP=clang++ CFLAGS="-c -w -fsanitize=address" LFLAGS="-g -lpthread -lm -w -fsanitize=address" INCLUDE_MAIN="-DINCLUDEMAIN -DOMITBAD" -j$(nproc) individuals > /dev/null
mmv \*.out \#1.asan

make clean > /dev/null
make CC=rezzanclang CPP=rezzanclang++ CFLAGS="-c -w -fno-builtin" LFLAGS="-g -lpthread -lm -w -fno-builtin" INCLUDE_MAIN="-DINCLUDEMAIN -DOMITBAD" -j$(nproc) individuals > /dev/null
mmv \*.out \#1.rezzan

make clean > /dev/null
REZZAN_NONCE_SIZE=64 make CC=rezzanclang CPP=rezzanclang++ CFLAGS="-c -w -fno-builtin" LFLAGS="-g -lpthread -lm -w -fno-builtin" INCLUDE_MAIN="-DINCLUDEMAIN -DOMITBAD" -j$(nproc) individuals > /dev/null
mmv \*.out \#1.lite

# Run
for asan_binary in `ls *.asan`
do
    ./${asan_binary} > /dev/null 2>&1
    asan_return_code=`echo $?`
    binary=${asan_binary%.*}
    ./${binary}.rezzan > /dev/null 2>&1
    rezzan_return_code=`echo $?`
    REZZAN_NONCE_SIZE=64 ./${binary}.lite > /dev/null 2>&1
    lite_return_code=`echo $?`

    
    if [ ${asan_return_code} -ne 0 ]
    then
        asan_return_code=1
    fi
    if [ ${rezzan_return_code} -ne 0 ]
    then
        rezzan_return_code=1
    fi
    if [ ${lite_return_code} -ne 0 ]
    then
        lite_return_code=1
    fi

    echo "${binary}, ${asan_return_code}, ${rezzan_return_code}, ${lite_return_code}" >> ${DIR}/results/${CWE}_good.csv
done



#!/bin/bash

# Create the folder for the results
rm -rf results
mkdir results

# Get the test suite
rm -rf 2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip
wget https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip
unzip 2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip

# Patch the random function
patch -p0 -i juliet.patch

# Clean invalid test cases
cd C/testcases
for folder in "CWE121_Stack_Based_Buffer_Overflow" "CWE122_Heap_Based_Buffer_Overflow" "CWE124_Buffer_Underwrite" "CWE126_Buffer_Overread" "CWE127_Buffer_Underread"; do
    cd $folder
    for subfolder in `ls`; do
        cd $subfolder
        ls | grep 'rand' | xargs rm -f
        ls | grep 'socket' | xargs rm -f
        ls | grep 'listen' | xargs rm -f
        ls | grep 'fscanf' | xargs rm -f
        ls | grep 'fgets' | xargs rm -f
        ls | grep 'sizeof' | xargs rm -f
        cd ..
    done
    cd ..
done

cd CWE416_Use_After_Free
ls | grep 'rand' | xargs rm -f
ls | grep 'socket' | xargs rm -f
ls | grep 'listen' | xargs rm -f
ls | grep 'fscanf' | xargs rm -f
ls | grep 'fgets' | xargs rm -f
ls | grep 'sizeof' | xargs rm -f
cd ..

rm -rf CWE124_Buffer_Underwrite/s04
rm -rf CWE126_Buffer_Overread/s03
rm -rf CWE127_Buffer_Underread/s04
rm -rf CWE416_Use_After_Free/CWE416_Use_After_Free__operator_equals_01*


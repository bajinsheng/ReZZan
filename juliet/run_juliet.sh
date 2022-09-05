#!/bin/bash -e

./setup_juliet.sh

./build_juliet_good.sh CWE121_Stack_Based_Buffer_Overflow
./build_juliet_good.sh CWE122_Heap_Based_Buffer_Overflow
./build_juliet_good.sh CWE124_Buffer_Underwrite
./build_juliet_good.sh CWE126_Buffer_Overread
./build_juliet_good.sh CWE127_Buffer_Underread
./build_juliet_good_CWE416.sh CWE416_Use_After_Free

./build_juliet_bad.sh CWE121_Stack_Based_Buffer_Overflow
./build_juliet_bad.sh CWE122_Heap_Based_Buffer_Overflow
./build_juliet_bad.sh CWE124_Buffer_Underwrite
./build_juliet_bad.sh CWE126_Buffer_Overread
./build_juliet_bad.sh CWE127_Buffer_Underread
./build_juliet_bad_CWE416.sh CWE416_Use_After_Free


python3 stat.py results
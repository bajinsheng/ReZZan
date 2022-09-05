# ReZZan: RET+Fuzzing+Sanitizer
ReZZan is a fast memory error sanitizer for fuzzing C/C++ code. 

## Publication
```Efficient Greybox Fuzzing to Detect Memory Errors``` (In the 37th IEEE/ACM International Conference on Automated Software Engineering [ASE22])

PDF: [https://arxiv.org/abs/2204.02773](https://arxiv.org/abs/2204.02773).


## Prerequisites

* LLVM >= 12
* Clang >= 12

## Build
```shell
sudo ./install.sh
```

## Run
You can directly call rezzan command, instead of clang, to compile your target program.
``` shell
rezzanclang target.c
./target
```
When a memory error happens, the target program will receive the SIGILL signal.

## Options
There are options to control the parameters of the ReZZan.
Note that these environment variables must be set for both compiling and running of target programs.
For example:
``` shell
REZZAN_NONCE_SIZE=64 rezzanclang target.c -o target
REZZAN_NONCE_SIZE=64 ./target
```

* `REZZAN_NONCE_SIZE`: size of the nonce in bits, must be {61,64}. 61 represents the byte-accurate detection, while 64 represents word-accurate detection. (Default: 61).
* `REZZAN_QUARANTINE_SIZE`: size of the quarantine, used for storing freed heap memory, in bytes (Default: ~1MB).
* `REZZAN_POOL_SIZE`: size of the memory pool in bytes (Default: ~2GB).
* `REZZAN_DEBUG`: set to 1 to enable debug output (Default: 0).
* `REZZAN_CHECKS`: set to 1 to enable additional checking for deubgging ReZZan (Default: 0).
* `REZZAN_DISABLED`: set to 1 to disable ReZZan allocation (Default: 0).
* `REZZAN_STATS`: set to 1 to print stats on exit (Default: 0).

## AFL 
### Build:
The same as the vanillan AFL
```
cd AFL
make clean all
cd llvm_mode
make clean all
```

### Run:
Setting AFL_CHECK_REZZAN environment to enable ReZZan in AFL.
```
AFL_CHECK_REZZAN=1 AFL/afl-clang-fast target.c -o target
./afl-fuzz -i in -o out -- ./target @@
```

### Demo:
To quickly start a fuzzing campaign:
```shell
git clone https://github.com/glennrp/libpng.git && \
    cd libpng && \
    CC=../AFL/afl-clang-fast ./configure --disable-shared --disable-libseccomp && \
    AFL_CHECK_REZZAN=1 make clean all
cd ..
mkdir in
echo "test" > in/test.txt
./AFL/afl-fuzz -i in -o out -- ./libpng/pngfix @@
```


## Artifact Evaluation
We provide a docker file to facilitate reproducing our results.

### Build:
```shell
sudo docker build . -t rezzan
```
### To Reproduce RQ.1 Detection Capability:
```shell
sudo docker run -it rezzan
cd /juliet
./run_juliet.sh
```
The final results will be shown in the terminal when the execution is done. Please see `juliet/Readme.md` for more information. The execution is expected to take several hours.

### To Reproduce RQ.2 Execution Speed:
```shell
sudo docker run -it rezzan
cd /benchmark
./run_benchmark.sh <fuzzer> <target>
```
Please choose the args from the following options:

fuzzer: {asan, rezzan, rezzan_lite, native}

target: {cxxfilt, file, jerryscript, mupdf, nm, objdump, libpng, size, sqlite, tcpdump}

The execution speed information will be shown in the terminal. Please see `benchmark/Readme.md` for more information.

### To Reproduce RQ.4 Bug Finding Effectiveness:
```shell
sudo docker run -it rezzan
cd /fuzzer-test-suite
./run_fuzzer-test-suite.sh <fuzzer> <target>
```
Please choose the args from the following options:

fuzzer: {asan, rezzan, rezzan_lite}

target: {c-ares-CVE-2016-5180, json-2017-02-12, libxml2-v2.9.2, openssl-1.0.1f, pcre2-10.00}

The fuzzing campaign will automatically stop when a crash found, so the time to reach this bug can be observed from the AFL GUI. More information please see `fuzzer-test-suite/Readme.md`

## License
This project is licensed under the GPL-3.0 - see the [LICENSE](./LICENSE) file for details. 

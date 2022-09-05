FROM ubuntu:20.04

ENV TZ=America/New_York
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt update && apt install -y apt-utils git autoconf cmake clang-12 llvm-12 gcc wget pkg-config build-essential zlib1g-dev libgcrypt20-dev libtool lzma subversion mmv unzip pip vim tclsh flex bison

RUN update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-12 1
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-12 1
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-12 1
RUN pip install numpy pandas

COPY AFL /AFL
COPY fuzzer-test-suite /fuzzer-test-suite
COPY juliet /juliet
COPY benchmark /benchmark
COPY rezzan_instrument.cpp /rezzan_instrument.cpp
COPY rezzan_runtime.c /rezzan_runtime.c
COPY clang++wrapper.c /clang++wrapper.c
COPY clangwrapper.c /clangwrapper.c
COPY install.sh /install.sh

# Install ReZZan
RUN /install.sh

# Compile AFL
RUN cd /AFL && make clean all && \
    cd llvm_mode && make clean all

ENV AFL_SKIP_CPUFREQ=1 \
    AFL_NO_AFFINITY=1

# Prepare benchmark
RUN cd /benchmark && ./setup_benchmark.sh
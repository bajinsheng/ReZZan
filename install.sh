#!/bin/bash

# Check the llvm version
clang_version=`clang --version | grep version`
if [[ ${clang_version} != *"12.0.0"* ]];then
    echo "Please use clang 12.0.0"
    exit 1
fi
llvm_version=`llvm-config --version`
if [[ ${llvm_version} != *"12.0.0"* ]];then
    echo "Please use llvm 12.0.0"
    exit 1
fi

# Compile the rezzan instrumentation module
clang++ `llvm-config --cxxflags` -Wl,-znodelete -fno-rtti -fPIC -shared rezzan_instrument.cpp -o rezzan.so `llvm-config --ldflags` || exit 0

# Compile the rezzan runtime library
gcc -g -fPIC -shared -o librezzan.so rezzan_runtime.c -O2 || exit 0

# Compile the compiler wrapper
clang clangwrapper.c -w -o clangwrapper || exit 0
clang clang++wrapper.c -w -o clang++wrapper || exit 0


# Clean installation folder
rm -Rf /opt/rezzan || exit 0
rm -rf /usr/bin/rezzanclang || exit 0
rm -rf /usr/bin/rezzanclang++ || exit 0


# Install
mkdir /opt/rezzan || exit 0
cp rezzan.so /opt/rezzan/rezzan.so || exit 0
cp clangwrapper /opt/rezzan/rezzanclang || exit 0
cp clang++wrapper /opt/rezzan/rezzanclang++ || exit 0
cp librezzan.so /lib/librezzan.so || exit 0
ln -s /opt/rezzan/rezzanclang /usr/bin/rezzanclang || exit 0
ln -s /opt/rezzan/rezzanclang++ /usr/bin/rezzanclang++ || exit 0



echo " ReZZan has been successfully installed."
echo " Usage: "
echo "      rezzanclang target.c -o target"
echo "      ./target"
echo " Enjoy it!"
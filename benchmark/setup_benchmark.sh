#!/bin/bash -e

# binutils: cxxfilt nm objdump size
rm -rf binutils-2.31.90*
wget https://sourceware.org/pub/binutils/snapshots/binutils-2.31.90.tar.xz
tar -xf binutils-2.31.90.tar.xz

# file
rm -rf file
rm -rf zlib
git clone https://github.com/file/file.git 
cd file && git checkout 6367a7c9b476767a692f76e78e3b355dc9386e48 && cd ..
git clone https://github.com/madler/zlib.git
cd zlib && git checkout cacf7f1d4e3d44d871b605da3b647f07d718623f && cd ..

# libpng
rm -rf libpng
git clone https://github.com/glennrp/libpng.git libpng

# tcpdump
rm -rf tcpdump
rm -rf libpcap
git clone https://github.com/the-tcpdump-group/tcpdump.git 
cd tcpdump && git checkout 0b3880c91e169db7cfbdce1b18ef4f1e3fd277de && cd ..
git clone https://github.com/the-tcpdump-group/libpcap.git
cd libpacp && git checkout 1a83bb6703bdcb3f07433521d95b788fa2ab4825 && cd ..

# jerryscript
rm -rf jerryscript
git clone https://github.com/jerryscript-project/jerryscript
cd jerryscript && git checkout 9ed695f9d29f841ae15f973e6e725d9c4b44ef51 && cd ..

# mupdf
rm -rf mupdf-1.19.0-source*
wget https://mupdf.com/downloads/archive/mupdf-1.19.0-source.tar.gz
tar -zxvf mupdf-1.19.0-source.tar.gz

# sqlite
rm -rf sqlite
tar -zxvf sqlite.tar.gz
#!/bin/bash

sudo apt update
git clone --recurse-submodules https://github.com/libbpf/bpftool.git

cd $HOME
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 428D7C01 C8CAB6595FDFF622
printf "deb http://ddebs.ubuntu.com %s main restricted universe multiverse\n" $(lsb_release -cs){,-updates,-security,-proposed} |  sudo tee -a /etc/apt/sources.list.d/ddebs.list
sudo apt update
sudo apt install linux-tools-$(uname -r) bpftrace clang libbpf-dev linux-headers-$(uname -r) git llvm bpftrace-dbgsym pkg-config make bpfcc-tools


git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src/
make
sudo make install




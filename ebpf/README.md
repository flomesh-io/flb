## This README is here for anyone who wants to build flb ebpf only modules

## Install Dependencies

### ubuntu 20.04
sudo apt -y install clang-10 llvm libelf-dev gcc-multilib libpcap-dev  
sudo apt -y install linux-tools-$(uname -r)  
sudo apt -y install elfutils dwarves  

### ubuntu 22.04
sudo apt -y install clang-13 llvm libelf-dev gcc-multilib libpcap-dev  
sudo apt -y install linux-tools-$(uname -r)  
sudo apt -y install elfutils dwarves  

## Build flb ebpf

cd -   
make  

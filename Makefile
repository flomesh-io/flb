#!make

SHELL = /bin/bash

clang ?= $(shell lsb_release -r | cut -f2 | sed s/22.04/clang-13/ | sed s/20.04/clang-10/)

kernel_version = $(shell uname -r | cut -d"-" -f1)
upgrade_version ?= $(shell apt list linux-image-5.*-generic 2>&1 | grep ^linux | cut -d '-' -f 3,4 | sort -rV | head -n1)

.PHONY: upgrade-kernel
upgrade-kernel:
	@dpkg --compare-versions $(kernel_version)  lt 5.7 ; \
	if [ $$? = 0 ]; then \
	  sudo apt install -y linux-modules-$(upgrade_version)-generic linux-headers-$(upgrade_version)-generic linux-image-$(upgrade_version)-generic || true; \
	  sudo apt -y --fix-broken install || true; \
	  sudo apt -y autoremove || true; \
	  echo -e "\E[33;7m System will automatically reboot in 10 seconds ... \E[0m\n\E[32;5m Cancel reboot by CTRL + C \E[0m" ;\
	  sleep 10; \
	  sudo systemctl reboot; \
	fi

.PHONY: install-depends
install-depends:
	@apt -y update
	@sudo apt -y install $(clang) llvm libelf-dev libpcap-dev
	@sudo apt -y install linux-tools-$(uname -r)
	@sudo apt -y install elfutils dwarves
	@arch=$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/) && echo $arch && if [ "$arch" = "arm64" ] ; then apt install -y gcc-multilib-arm-linux-gnueabihf; else apt update && apt install -y gcc-multilib;fi
	@sudo apt -y autoremove

.PHONY: install-ftc
install-ftc:
	@sudo apt -y install libbsd-dev
	@sudo apt -y install unzip wget bison flex pkg-config
	@rm -rf flb.zip iproute2-flb
	@if [ ! -f /usr/local/sbin/ftc ]; then wget https://github.com/cybwan/iproute2/archive/refs/heads/flb.zip && unzip flb.zip && cd iproute2-flb/libbpf/src/ && mkdir build && DESTDIR=build make install && cd - && cd iproute2-flb/ && export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:`pwd`/libbpf/src/ && LIBBPF_FORCE=on LIBBPF_DIR=`pwd`/libbpf/src/build ./configure && make && cp -f tc/tc /usr/local/sbin/ftc && cd - && cd iproute2-flb/libbpf/src/ && make install && cd - && rm -fr flb.zip iproute2-flb; fi

.PHONY: install-bpftool
install-bpftool:
	@rm -fr bpftool
	@sudo apt -y install git unzip
	@if [ ! -f /usr/local/sbin/bpftool ]; then git clone --recurse-submodules https://github.com/libbpf/bpftool.git && cd bpftool/src/ && make clean && make -j $(nproc) && cp -f ./bpftool /usr/local/sbin/bpftool && cd - && rm -fr bpftool; fi

.PHONY: install-golang
install-golang:
	@if [ ! -f /snap/bin/go ]; then snap install go --classic; fi

.PHONY: install-test-tools
install-test-tools:
	@sudo apt -y install net-tools bridge-utils arping build-essential iproute2 tcpdump iputils-ping keepalived curl bash-completion

subsys:
	@sudo mkdir -p /opt/flb/cert
	@sudo cp ebpf/cert/* /opt/flb/cert/
	@cd ebpf && make

subsys-clean:
	@cd ebpf && make clean

.PHONY: go-mod-tidy
go-mod-tidy:
	@go mod tidy

.PHONY: simulator-build
simulator-build:
	CGO_ENABLED=1 go build -v -o ./bin/simulator ./boot/simulator/*

.PHONY: simulator-run
simulator-run:
	./bin/simulator

.PHONY: simulator
simulator: simulator-build simulator-run

.PHONY: flb-build
flb-build:
	@CGO_ENABLED=1 go build -v -o ./bin/flb ./boot/flb/*

.PHONY: flb-run
flb-run:
	@./bin/flb

.PHONY: flb
flb: flb-build flb-run

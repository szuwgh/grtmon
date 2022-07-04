
GOCMD := go
RUSTCMD := cargo build
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CMD_CLANG := clang


GO_SOURCE := main.go
GO_BINARY := villus

all: build_go

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)

build:
	clang -O2 -mcpu=v1 -O2 -g -Wall -Werror -DOUTPUT_SKB -D__TARGET_ARCH_x86 -I./bpf/headers -target bpfel -c /opt/goproject/villus/src/github.com/szuwgh/villus/bpf/kprobe/kprobe.c -o /opt/goproject/villus/src/github.com/szuwgh/villus/bpf_bpfel.o -fno-ident -fdebug-prefix-map=/opt/goproject/villus/src/github.com/szuwgh/villus/bpf/kprobe=bpf/kprobe -fdebug-compilation-dir . -g 
	$(GOBUILD) -v -o $(GO_BINARY)  

GOCMD := go
RUSTCMD := cargo build
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CMD_CLANG := clang


GO_SOURCE := main.go
GO_BINARY := grtmon

all: build_go

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)

build:
	cd user/ && go generate 
	$(GOBUILD) -v -o $(GO_BINARY)  
	
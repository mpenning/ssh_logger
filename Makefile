# Makefile color codes...
#     ref -> https://stackoverflow.com/a/5947802/667301
COL_GREEN=\033[0;32m
COL_CYAN=\033[0;36m
COL_YELLOW=\033[0;33m
COL_RED=\033[0;31m
COL_END=\033[0;0m

.DEFAULT_GOAL := all

get_mod_latest:
	@echo "$(COL_CYAN)>> build a NEW go.mod and compile$(COL_END)"
	# build a **new** go.mod file
	-rm go.mod
	go mod init ssh_logger
	go mod tidy
.PHONY: get_mod_latest

fmt:
	@echo "$(COL_GREEN)>> reformatting with 'go fmt'$(COL_END)"
	go fmt *.go
.PHONY: fmt

all:
	make fmt
	go build -ldflags "-s -w" -o ssh_logger main.go
.PHONY: all


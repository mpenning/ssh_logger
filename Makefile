# Makefile color codes...
#     ref -> https://stackoverflow.com/a/5947802/667301
COL_GREEN=\033[0;32m
COL_CYAN=\033[0;36m
COL_YELLOW=\033[0;33m
COL_RED=\033[0;31m
COL_END=\033[0;0m

.DEFAULT_GOAL := all

# This is NOT run by default
revise_go_mod:
	@echo "$(COL_CYAN)>> Revise go.mod, and compile$(COL_END)"
	# build a **new** go.mod file
	-rm go.mod
	go mod init ssh_logger
	go mod tidy
.PHONY: revise_go_mod

# This is run by default
fmt:
	@echo "$(COL_GREEN)>> reformatting with 'go fmt'$(COL_END)"
	go fmt *.go
.PHONY: fmt

all:
	make fmt
	go build -ldflags "-s -w" -o ssh_logger main.go
.PHONY: all

test:
	make all
	@echo "$(COL_GREEN)>> Test w/ no auth to route-views.routeviews.org$(COL_END)"
	## ping with an IP address for a deterministic test timeout
	ping -W1 -c2 4.2.2.2
	## Run an SSH test to route-views.routeviews.org
	./ssh_logger --yaml configs/route_views.yaml
.PHONY: test

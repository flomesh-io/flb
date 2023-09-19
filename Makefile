#!make

.PHONY: go-mod-tidy
go-mod-tidy:
	@go mod tidy

.PHONY: nat-build
nat-build:
	CGO_ENABLED=1 go build -v -o ./bin/nat ./cmd/nat/*

.PHONY: nat-run
nat-run:
	./bin/nat


.PHONY: l2addr-build
l2addr-build:
	CGO_ENABLED=1 go build -v -o ./bin/l2addr ./cmd/l2addr/*

.PHONY: l2addr-run
l2addr-run:
	./bin/l2addr

.PHONY: intf-build
intf-build:
	CGO_ENABLED=1 go build -v -o ./bin/intf ./cmd/intf/*

.PHONY: intf-run
intf-run:
	./bin/intf

.PHONY: route-build
route-build:
	CGO_ENABLED=1 go build -v -o ./bin/route ./cmd/route/*

.PHONY: route-run
route-run:
	./bin/route

.PHONY: routermac-build
routermac-build:
	CGO_ENABLED=1 go build -v -o ./bin/routermac ./cmd/routermac/*

.PHONY: routermac-run
routermac-run:
	./bin/routermac

.PHONY: nexthop-build
nexthop-build:
	CGO_ENABLED=1 go build -v -o ./bin/nexthop ./cmd/nexthop/*

.PHONY: nexthop-run
nexthop-run:
	./bin/nexthop

.PHONY: mirror-build
mirror-build:
	CGO_ENABLED=1 go build -v -o ./bin/mirror ./cmd/mirror/*

.PHONY: mirror-run
mirror-run:
	./bin/mirror

.PHONY: polx-build
polx-build:
	CGO_ENABLED=1 go build -v -o ./bin/polx ./cmd/polx/*

.PHONY: polx-run
polx-run:
	./bin/polx

.PHONY: netlink-build
netlink-build:
	CGO_ENABLED=1 go build -v -o ./bin/netlink ./cmd/netlink/*

.PHONY: netlink-run
netlink-run:
	./bin/netlink
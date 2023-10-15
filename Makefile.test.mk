#!make

ARCH ?= $(shell arch)

PIPY ?= 0.90.3-2

.PHONY: pipy
pipy:
	@if [ ! -f /usr/local/bin/pipy ]; then wget https://github.com/flomesh-io/pipy/releases/download/$(PIPY)/pipy-$(PIPY)-generic_linux-$(ARCH).tar.gz && tar zxf pipy-$(PIPY)-generic_linux-$(ARCH).tar.gz && cp usr/local/bin/pipy /usr/local/bin && rm -rf pipy-$(PIPY)-generic_linux-$(ARCH).tar.gz usr; fi

.PHONY: up-ep1
up-ep1:
	# Configure load-balancer end-point ep1
	@sudo ip netns add ep1
	@sudo ip link add eflb0ep1 type veth peer name eep1flb0 netns ep1
	@sudo ip link set eflb0ep1 mtu 9000 up
	@sudo ip addr add 31.31.31.254/24 dev eflb0ep1
	@sudo ip -n ep1 link set eep1flb0 mtu 7000 up
	@sudo ip netns exec ep1 ifconfig eep1flb0 31.31.31.1/24 up
	@sudo ip netns exec ep1 ip route add default via 31.31.31.254
	@sudo ip netns exec ep1 ifconfig lo up
	@sudo ip netns exec ep1 pipy -e "pipy().listen('31.31.31.1:8080').serveHTTP(new Message('Hi, I am from ep1.\n'))" 1>/dev/null 2>&1 &
	@sleep 2
	@ping 31.31.31.1 -c 2
	@sudo ip netns exec ep1 ping 31.31.31.254 -c 2
	@curl 31.31.31.1:8080

.PHONY: up-ep2
up-ep2:
	# Configure load-balancer end-point ep2
	@sudo ip netns add ep2
	@sudo ip link add eflb0ep2 type veth peer name eep2flb0 netns ep2
	@sudo ip link set eflb0ep2 mtu 9000 up
	@sudo ip addr add 32.32.32.254/24 dev eflb0ep2
	@sudo ip -n ep2 link set eep2flb0 mtu 7000 up
	@sudo ip netns exec ep2 ifconfig eep2flb0 32.32.32.1/24 up
	@sudo ip netns exec ep2 ip route add default via 32.32.32.254
	@sudo ip netns exec ep2 ifconfig lo up
	@sudo ip netns exec ep2 pipy -e "pipy().listen('32.32.32.1:8080').serveHTTP(new Message('Hi, I am from ep2.\n'))" 1>/dev/null 2>&1 &
	@sleep 2
	@ping 32.32.32.1 -c 2
	@sudo ip netns exec ep2 ping 32.32.32.254 -c 2
	@curl 32.32.32.1:8080

.PHONY: up-ep3
up-ep3:
	# Configure load-balancer end-point ep3
	@sudo ip netns add ep3
	@sudo ip link add eflb0ep3 type veth peer name eep3flb0 netns ep3
	@sudo ip link set eflb0ep3 mtu 9000 up
	@sudo ip addr add 33.33.33.254/24 dev eflb0ep3
	@sudo ip -n ep3 link set eep3flb0 mtu 7000 up
	@sudo ip netns exec ep3 ifconfig eep3flb0 33.33.33.1/24 up
	@sudo ip netns exec ep3 ip route add default via 33.33.33.254
	@sudo ip netns exec ep3 ifconfig lo up
	@sudo ip netns exec ep3 pipy -e "pipy().listen('33.33.33.1:8080').serveHTTP(new Message('Hi, I am from ep3.\n'))" 1>/dev/null 2>&1 &
	@sleep 2
	@ping 33.33.33.1 -c 2
	@sudo ip netns exec ep3 ping 33.33.33.254 -c 2
	@curl 33.33.33.1:8080

.PHONY: up-h1
up-h1:
	# Configure load-balancer end-point h1
	@sudo ip netns add h1
	@sudo ip link add eflb0h1 type veth peer name eh1flb0 netns h1
	@sudo ip link set eflb0h1 mtu 9000 up
	@sudo ip addr add 10.10.10.254/24 dev eflb0h1
	@sudo ip -n h1 link set eh1flb0 mtu 7000 up
	@sudo ip netns exec h1 ifconfig eh1flb0 10.10.10.1/24 up
	@sudo ip netns exec h1 ip route add default via 10.10.10.254
	@sudo ip netns exec h1 ifconfig lo up
	@sleep 2
	@ping 10.10.10.1 -c 2
	@sudo ip netns exec h1 ping 10.10.10.254 -c 2

.PHONY: down-ep1
down-ep1:
	@sudo ip l del dev eflb0ep1
	@sudo ip netns delete ep1

.PHONY: down-ep2
down-ep2:
	@sudo ip l del dev eflb0ep2
	@sudo ip netns delete ep2

.PHONY: down-ep3
down-ep3:
	@sudo ip link del dev eflb0ep3
	@sudo ip netns delete ep3

.PHONY: down-h1
down-h1:
	@sudo ip link del dev eflb0h1
	@sudo ip netns delete h1

EP_TARGETS = ep1 ep2 ep3 h1
$(foreach target,$(EP_TARGETS),$(eval up-$(target): pipy))

UP_TARGETS = $(addprefix up-, $(EP_TARGETS))
DOWN_TARGETS = $(addprefix down-,$(EP_TARGETS))

.PHONY: test-up
test-up: $(UP_TARGETS)

.PHONY: test-down
test-down: $(DOWN_TARGETS)

.PHONY: test-apply-lb
test-apply-lb:
	@curl -X PUT -H "Content-Type: application/json" -d '{"LbRules":[{"serviceArguments":{"externalIP":"20.20.20.1","port":8080,"protocol":"tcp","block":0,"sel":0,"monitor":false,"mode":0,"inactiveTimeout":0,"managed":false,"probetype":"","probeport":0,"probereq":"","proberesp":""},"secondaryIPs":null,"endpoints":[{"endpointIP":"31.31.31.1","targetPort":8080,"weight":1,"state":""},{"endpointIP":"32.32.32.1","targetPort":8080,"weight":1,"state":""},{"endpointIP":"33.33.33.1","targetPort":8080,"weight":1,"state":""}]}]}' http://127.0.0.1:19090

.PHONY: test
test:
	@ip netns exec h1 curl 20.20.20.1:8080
	@ip netns exec h1 curl 20.20.20.1:8080
	@ip netns exec h1 curl 20.20.20.1:8080
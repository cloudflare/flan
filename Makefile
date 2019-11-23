SUDO ?= $(shell if ! groups | grep -q docker; then echo sudo; fi)

build : 
	$(SUDO) docker build -t flan_scan .

container_name = flan_$(shell date +'%s')
start : 
	$(SUDO) docker run --name $(container_name) -v $(shell pwd)/shared:/shared flan_scan

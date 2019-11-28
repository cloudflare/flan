build : 
	docker build -t flan_scan .
pull :
	docker pull chko/flan
	docker image tag chko/flan flan_scan
container_name = flan_$(shell date +'%s')
start : 
	docker run --name $(container_name) -v $(shell pwd)/shared:/shared flan_scan

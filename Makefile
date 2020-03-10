build : 
	docker build -t flan_scan .

container_name = flan_$(shell date +'%s')
start : 
	docker run --name $(container_name) -v "$(CURDIR)/shared:/shared:Z" flan_scan

all: build-docker upload-docker

build-docker:
	docker build -t netwatchteam/netwatch_ssh-attackpod:9.6 .
	#docker build -t netwatchteam/netwatch_ssh-attackpod:9.6-amd64 .

	#docker build -t docker.netwatch.team/netwatch_ssh-attackpod:9.6 .

upload-docker:
	docker push netwatchteam/netwatch_ssh-attackpod:9.6
	#docker push netwatchteam/netwatch_ssh-attackpod:9.6-amd64

	#docker push docker.netwatch.team/netwatch_ssh-attackpod:9.6

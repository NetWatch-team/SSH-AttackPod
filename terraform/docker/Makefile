all: build-docker upload-docker

build-docker:
	docker build -t netwatchteam/netwatch_ssh-attackpod:latest -t netwatchteam/netwatch_ssh-attackpod:9.6 .

upload-docker:
	docker push netwatchteam/netwatch_ssh-attackpod:latest
	docker push netwatchteam/netwatch_ssh-attackpod:9.6

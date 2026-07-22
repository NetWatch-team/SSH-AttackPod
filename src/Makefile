VERSION ?= 9.6

all: build-docker upload-docker

build-docker:
	docker build -t netwatchteam/netwatch_ssh-attackpod:latest -t netwatchteam/netwatch_ssh-attackpod:$(VERSION) -t ghcr.io/netwatch-team/ssh-attackpod:latest -t ghcr.io/netwatch-team/ssh-attackpod:$(VERSION) .

upload-docker:
	docker push netwatchteam/netwatch_ssh-attackpod:latest
	docker push netwatchteam/netwatch_ssh-attackpod:$(VERSION)
	docker push ghcr.io/netwatch-team/ssh-attackpod:latest
	docker push ghcr.io/netwatch-team/ssh-attackpod:$(VERSION)

APP_NAME := morty
IMAGE ?= localhost/$(APP_NAME):latest
PORT ?= 3000

.PHONY: all fmt vet lint test bench build image run stop zizmor clean

all: fmt vet test build

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -d . && exit 1)

vet:
	go vet ./...

lint:
	golangci-lint run ./...

test:
	go test -race -count=1 ./...

bench:
	go test -benchmem -bench . -run '^$$'

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o $(APP_NAME) .

image:
	podman build -t $(IMAGE) .

run:
	podman run --rm -d --name $(APP_NAME) -p 127.0.0.1:$(PORT):3000 $(IMAGE)

stop:
	-podman stop $(APP_NAME)

zizmor:
	zizmor .

clean:
	rm -f $(APP_NAME)

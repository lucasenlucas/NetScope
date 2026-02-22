.PHONY: build clean

APP_NAME=netscope
VERSION=4.0.1

build:
	go build -ldflags "-s -w -X main.version=${VERSION}" -o ${APP_NAME} *.go

clean:
	rm -f ${APP_NAME}

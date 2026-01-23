APP=lucasdns

.PHONY: build run tidy

build:
	go build -o bin/$(APP) .

run:
	go run . --help

tidy:
	go mod tidy


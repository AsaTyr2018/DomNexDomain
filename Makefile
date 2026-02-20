BINARY=domnexdomain

.PHONY: build test tidy

build:
	go build -o build/$(BINARY) ./cmd/domnexdomain

test:
	go test ./...

tidy:
	go mod tidy

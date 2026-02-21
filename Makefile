BINARY=domnexdomain

.PHONY: build test tidy build-ui publish-local

build:
	go build -o build/$(BINARY) ./cmd/domnexdomain

build-ui:
	cd ui && npm run build

publish-local:
	bash scripts/publish_local.sh

test:
	go test ./...

tidy:
	go mod tidy

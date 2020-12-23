BIN = insider
BUILDFLAGS := '-w -s'
GO := GO111MODULE=on go


test:
	$(GO) test -v -race ./...

coverage:
	$(GO) test -v -race -coverprofile=cover.out ./...
	$(GO) tool cover -html=cover.out

build:
	$(GO) build -o $(BIN) ./cmd/insider/

build-release:
	CGO_ENABLED=0 $(GO) build -ldflags $(BUILDFLAGS) -o $(BIN) ./cmd/insider/

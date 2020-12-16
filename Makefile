BIN = insider
BUILDFLAGS := '-w -s'
GO := GO111MODULE=on go


test:
	$(GO) test -v -race ./...

build:
	$(GO) build -o $(BIN) ./cmd/insider/

build-release:
	$(GO) build -ldflags $(BUILDFLAGS) -o $(BIN) ./cmd/insider/


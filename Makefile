BUILD_FLAGS = -a -ldflags '-s -w' -buildmode=pie
GO_FLAGS =  -x
NT_BUILD_FLAGS = -a -ldflags '-s -w' -buildmode=exe

run_tests:
	@ go clean -testcache
	@ go test -v ./...

buildDebug:
	@ go build -o insider

build:
	@ GOOS=linux GOARCH=386 go build ${BUILD_FLAGS} ${GO_FLAGS} -o insider

buildWindows:
	@ GOOS=windows GOARCH=386 go build ${NT_BUILD_FLAGS} ${GO_FLAGS} -o insider.exe

BUILD_FLAGS = -a -ldflags '-s -w' -buildmode=pie
GO_FLAGS =  -x
NT_BUILD_FLAGS = -a -ldflags '-s -w' -buildmode=exe

buildDebug:
	@ go build -o insider

macos:
	@ GOOS=darwin GOARCH=amd64 go build -o insider-macos-amd64
linux64:
	@ GOOS=linux GOARCH=amd64 go build ${BUILD_FLAGS} ${GO_FLAGS} -o insider-linux-amd64
linux32:
	@ GOOS=linux GOARCH=386 go build  ${GO_FLAGS} -o insider-linux-x86
win32:
	@ GOOS=windows GOARCH=386 go build ${NT_BUILD_FLAGS} ${GO_FLAGS} -o insider-x86.exe
win64:
	@ GOOS=windows GOARCH=amd64 go build ${NT_BUILD_FLAGS} ${GO_FLAGS} -o insider-x64.exe
all:
	@ GOOS=linux GOARCH=amd64 go build ${BUILD_FLAGS} ${GO_FLAGS} -o insider-linux-amd64
	@ GOOS=linux GOARCH=386 go build  ${GO_FLAGS} -o insider-linux-x86
	@ GOOS=windows GOARCH=386 go build ${NT_BUILD_FLAGS} ${GO_FLAGS} -o insider-x86.exe
	@ GOOS=windows GOARCH=amd64 go build ${NT_BUILD_FLAGS} ${GO_FLAGS} -o insider-x64.exe
	@ GOOS=darwin GOARCH=amd64 go build -o insider-macos-amd64

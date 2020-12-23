ARG GO_VERSION
FROM golang:${GO_VERSION} AS builder
WORKDIR /build
COPY . /build/
RUN go mod download
RUN make build-release

FROM alpine
WORKDIR /opt/insider
COPY --from=builder /build/insider /opt/insider/insider
ENTRYPOINT [ "./insider" ]

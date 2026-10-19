# syntax=docker/dockerfile:1
ARG GO_IMAGE=golang:1.27.2-bookworm
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
COPY *.go .
COPY packaging packaging
COPY UNICODE-LICENSE.txt .
COPY --from=project-license LICENSE /LICENSE
COPY --from=project-license NOTICE /NOTICE
COPY --from=test-vectors . /test-vectors
ENV DIRHASH_TEST_VECTORS=/test-vectors
RUN set -eu; \
    unformatted=$(gofmt -l .); \
    if [ -n "$unformatted" ]; then \
        printf 'Go formatting required; run gofmt on:\n%s\n' "$unformatted" >&2; \
        exit 1; \
    fi; \
    go vet ./... \
    && go test ./...
RUN mkdir /out \
    && GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/dirhash-linux-amd64 . \
    && GOOS=linux GOARCH=arm64 GOARM64=v8.0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/dirhash-linux-arm64 . \
    && GOOS=windows GOARCH=amd64 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/dirhash-windows-amd64.exe . \
    && go run ./packaging /out \
    && cp /LICENSE /NOTICE /out/

FROM scratch AS artifacts
COPY --from=build /out/ /

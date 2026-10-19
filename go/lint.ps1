$ErrorActionPreference = 'Stop'

$Source = $PSScriptRoot
& docker run --rm --mount "type=bind,source=$Source,target=/src" `
    --mount type=volume,source=dirhash-go-mod,target=/go/pkg/mod `
    --mount type=volume,source=dirhash-go-cache,target=/root/.cache/go-build `
    -w /src golang:1.27.2-bookworm sh -c `
    'GOBIN=/src/.lintbin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 && .lintbin/golangci-lint run && GOOS=windows .lintbin/golangci-lint run; status=$?; rm -rf .lintbin; exit $status'
if ($LASTEXITCODE -ne 0) {
    throw "Go lint failed with exit code $LASTEXITCODE."
}

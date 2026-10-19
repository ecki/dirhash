$ErrorActionPreference = 'Stop'

& (Join-Path $PSScriptRoot 'build.ps1')
& docker build --file (Join-Path $PSScriptRoot 'tests\Dockerfile') `
    --tag dirhash-conformance $PSScriptRoot
if ($LASTEXITCODE -ne 0) {
    throw "Conformance image build failed with exit code $LASTEXITCODE."
}
& docker run --rm dirhash-conformance
if ($LASTEXITCODE -ne 0) {
    throw "Conformance tests failed with exit code $LASTEXITCODE."
}

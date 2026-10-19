$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$Destination = Join-Path (Join-Path $Root 'dist') 'go'
$Dockerfile = Join-Path $PSScriptRoot 'Dockerfile'
$Vectors = Join-Path (Join-Path $Root 'tests') 'vectors'

& docker buildx build --target artifacts --file $Dockerfile `
    --build-context "test-vectors=$Vectors" `
    --build-context "project-license=$Root" `
    --output "type=local,dest=$Destination" $PSScriptRoot
if ($LASTEXITCODE -ne 0) {
    throw "Go container build failed with exit code $LASTEXITCODE."
}

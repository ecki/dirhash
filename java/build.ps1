$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$Destination = Join-Path (Join-Path $Root 'dist') 'java'
$Dockerfile = Join-Path $PSScriptRoot 'Dockerfile'

& docker buildx build --target artifacts --file $Dockerfile `
    --build-context "test-vectors=$(Join-Path (Join-Path $Root 'tests') 'vectors')" `
    --build-context "project-license=$Root" `
    --output "type=local,dest=$Destination" $PSScriptRoot
if ($LASTEXITCODE -ne 0) {
    throw "Java container build failed with exit code $LASTEXITCODE."
}

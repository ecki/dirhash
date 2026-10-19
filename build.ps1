param(
    [ValidateSet('All', 'Java', 'Go')]
    [string]$Ecosystem = 'All'
)

$ErrorActionPreference = 'Stop'

foreach ($Name in @('Java', 'Go')) {
    if ($Ecosystem -ne 'All' -and $Ecosystem -ne $Name) {
        continue
    }

    $Directory = $Name.ToLowerInvariant()
    & (Join-Path (Join-Path $PSScriptRoot $Directory) 'build.ps1')
}

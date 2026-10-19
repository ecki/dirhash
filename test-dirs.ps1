#Requires -Version 7.0
param(
    [Parameter(Mandatory, Position = 0)]
    [string[]]$Directories,
    [string]$JavaExecutable = 'java',
    [string]$JarPath = (Join-Path $PSScriptRoot 'dist\java\dirhash.jar'),
    [string]$GoExecutable = (Join-Path $PSScriptRoot 'dist\go\dirhash-windows-amd64.exe'),
    [ValidateSet('Tree', 'Plain')]
    [string]$Mode = 'Tree',
    [ValidateSet('sha1', 'sha256', 'sha512', 'blake2b-256', 'blake2b-512',
        'blake3', 'sha3-256', 'sha3-512')]
    [string[]]$Algorithms = @('sha1', 'sha256'),
    [ValidateSet('h1', 'h1-go', 'gittree', 'swhid', 'nar')]
    [string[]]$Schemes = @('h1', 'h1-go', 'gittree', 'swhid', 'nar'),
    [ValidateSet('Strict', 'NonStrict')]
    [string[]]$StrictModes = @('NonStrict', 'Strict'),
    [ValidateRange(1, 86400)]
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
$Digests = @($Algorithms | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
if ($Digests.Count -eq 0) { throw 'Specify at least one algorithm.' }
$Schemes = @($Schemes | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
$StrictModes = @($StrictModes | Select-Object -Unique)
if ($Schemes.Count -eq 0 -or $StrictModes.Count -eq 0) {
    throw 'Specify at least one scheme and strict mode.'
}
$Roots = @($Directories | ForEach-Object {
    $Item = Get-Item -LiteralPath $_
    if (-not $Item.PSIsContainer -or $Item.PSProvider.Name -ne 'FileSystem') {
        throw "Not a filesystem directory: $_"
    }
    $Item.FullName
})
$JarPath = (Get-Item -LiteralPath $JarPath).FullName
$GoExecutable = (Get-Item -LiteralPath $GoExecutable).FullName

function Invoke-Backend {
    param([string]$Executable, [string[]]$Arguments)
    $Start = [System.Diagnostics.ProcessStartInfo]::new()
    $Start.FileName = $Executable
    $Start.UseShellExecute = $false
    $Start.RedirectStandardOutput = $true
    $Start.RedirectStandardError = $true
    $Start.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $Start.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    foreach ($Argument in $Arguments) {
        $Start.ArgumentList.Add($Argument)
    }
    $Process = [System.Diagnostics.Process]::new()
    $Process.StartInfo = $Start
    try {
        if (-not $Process.Start()) { throw "Could not start $Executable" }
        $Output = $Process.StandardOutput.ReadToEndAsync()
        $Errors = $Process.StandardError.ReadToEndAsync()
        if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
            $Process.Kill($true)
            $Process.WaitForExit()
            throw "$Executable exceeded the $TimeoutSeconds second timeout."
        }
        [pscustomobject]@{
            Code = $Process.ExitCode
            Out = $Output.GetAwaiter().GetResult()
            Err = $Errors.GetAwaiter().GetResult()
        }
    } finally {
        $Process.Dispose()
    }
}

function Test-Invocation {
    param([string[]]$Arguments, [string]$Selection)
    $Java = Invoke-Backend $JavaExecutable (@('-jar', $JarPath) + $Arguments)
    $Go = Invoke-Backend $GoExecutable $Arguments
    $Context = $Arguments -join ' '
    if ($Java.Code -ne $Go.Code -or $Java.Out -cne $Go.Out) {
        throw "Backend mismatch: $Context`nJava exit $($Java.Code): $($Java.Out)$($Java.Err)`nGo exit $($Go.Code): $($Go.Out)$($Go.Err)"
    }
    if ($Java.Code -ne 0) {
        if ($Java.Out.Length -ne 0 -or $Java.Err -notmatch '^([A-Z_]+)' -or
            $Go.Err -notmatch '^([A-Z_]+)') {
            throw "Invalid failure output: $Context"
        }
        $JavaCategory = [regex]::Match($Java.Err, '^([A-Z_]+)').Value
        $GoCategory = [regex]::Match($Go.Err, '^([A-Z_]+)').Value
        if ($Java.Code -eq 2 -or $JavaCategory -cne $GoCategory) {
            throw "Rejected selection or differing failure category: $Context`nJava: $($Java.Err)`nGo: $($Go.Err)"
        }
        return 'Rejected'
    }
    if ($Java.Err -cne $Go.Err) {
        throw "Warning mismatch: $Context`nJava: $($Java.Err)`nGo: $($Go.Err)"
    }
    if ($Java.Err.Length -ne 0) {
        foreach ($Line in ($Java.Err.TrimEnd() -split '\r?\n')) {
            if ($Line -notmatch '^WARN_ZIP_DIRECTORY_(MODE|SLASH): ') {
                throw "Unexpected stderr: $Context`nJava: $($Java.Err)`nGo: $($Go.Err)"
            }
        }
        $script:WarningInvocations++
    }
    $Document = ConvertFrom-Json -InputObject $Java.Out
    $Parts = $Selection.Substring(2).Split(':')
    if ($Document.schemaVersion -ne 1 -or @($Document.results).Count -eq 0) {
        throw "Missing results: $Context"
    }
    foreach ($Record in $Document.results) {
        if ($Record.scheme -cne $Parts[0] -or $Record.digestAlgorithm -cne $Parts[1]) {
            throw "Unexpected scheme/digest in result: $Context"
        }
    }
    return 'Succeeded'
}

function Compare-Invocation {
    param([string[]]$Arguments, [string]$Selection)
    $StrictLabel = if ($Arguments -contains '--strict') { 'strict' } else { 'non-strict' }
    Write-Host "Processing $Selection [$StrictLabel]: $($Arguments[-1])"
    try {
        $Outcome = Test-Invocation $Arguments $Selection
        if ($Outcome -eq 'Rejected') {
            $script:Rejected++
        } else {
            $script:Succeeded++
        }
    } catch {
        $script:Differences++
        Write-Host "DIFFERENCE: $($_.Exception.Message)"
    }
}

function Test-ArchiveCandidate {
    param([System.IO.FileInfo]$File)
    if ($File.Name -match '(?i)\.(zip|jar|war|ear|tar|tar\.gz|tgz)$') {
        return $true
    }
    $Stream = $File.OpenRead()
    try {
        $Header = [byte[]]::new(512)
        $Count = 0
        while ($Count -lt $Header.Length) {
            $Read = $Stream.Read($Header, $Count, $Header.Length - $Count)
            if ($Read -eq 0) { break }
            $Count += $Read
        }
        if ($Count -ge 2 -and $Header[0] -eq 31 -and $Header[1] -eq 139) {
            return $true
        }
        if ($Count -ge 4 -and $Header[0] -eq 80 -and $Header[1] -eq 75 -and
            (($Header[2] -eq 3 -and $Header[3] -eq 4) -or
             ($Header[2] -eq 5 -and $Header[3] -eq 6) -or
             ($Header[2] -eq 6 -and $Header[3] -eq 6))) {
            return $true
        }
        if ($Count -lt 512) { return $false }
        $ChecksumField = [System.Text.Encoding]::ASCII.GetString($Header, 148, 8).Trim([char[]]@(0, 32))
        if ($ChecksumField -notmatch '^[0-7]+$') { return $false }
        $Sum = 0
        $SignedSum = 0
        for ($Index = 0; $Index -lt 512; $Index++) {
            $Byte = if ($Index -ge 148 -and $Index -lt 156) { 32 } else { [int]$Header[$Index] }
            $Sum += $Byte
            $SignedSum += $(if ($Byte -ge 128) { $Byte - 256 } else { $Byte })
        }
        $Expected = [Convert]::ToInt32($ChecksumField, 8)
        return $Expected -eq $Sum -or $Expected -eq $SignedSum
    } finally {
        $Stream.Dispose()
    }
}

$Comparisons = 0
$Succeeded = 0
$Rejected = 0
$Differences = 0
$WarningInvocations = 0
$ArchivesFound = 0
foreach ($Root in $Roots) {
    $Archives = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    if ($Mode -eq 'Plain') {
        foreach ($File in (Get-ChildItem -LiteralPath $Root -File -Recurse -Force)) {
            if (($File.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                continue
            }
            if (Test-ArchiveCandidate $File) {
                $null = $Archives.Add($File.FullName)
            }
        }
    }
    foreach ($StrictMode in $StrictModes) {
        $Options = @('--recurse', '--format=json')
        if ($StrictMode -eq 'Strict') { $Options += '--strict' }
        if ($Mode -eq 'Tree') {
            foreach ($Scheme in $Schemes) {
                foreach ($Digest in $Digests) {
                    $Selection = "--${Scheme}:$Digest"
                    Compare-Invocation ($Options + @($Selection, '--', $Root)) $Selection
                    $Comparisons++
                }
            }
        }
        if ($Mode -eq 'Plain') {
            foreach ($Archive in ($Archives | Sort-Object)) {
                foreach ($Digest in $Digests) {
                    $Selection = "--plain:$Digest"
                    Compare-Invocation ($Options + @($Selection, '--', $Archive)) $Selection
                    $Comparisons++
                }
            }
        }
    }
    $ArchivesFound += $Archives.Count
}
Write-Host "Mode: $Mode; directories: $($Roots.Count); comparisons: $Comparisons; matching hashes: $Succeeded; matching rejections: $Rejected; matching warning runs: $WarningInvocations; differences/errors: $Differences; plain archive roots: $ArchivesFound"
if ($Differences -gt 0) {
    exit 1
}
exit 0

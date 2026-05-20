param(
    [string]$Python = "",
    [string]$DataDir = "D:\UFID-data",
    [string]$HostName = "127.0.0.1",
    [int]$Port = 8765,
    [int]$PortScanCount = 20,
    [string]$Collection = "vintagesoftware",
    [string]$Query = "",
    [string]$CrawlName = "",
    [int]$MaxItems = 0,
    [int]$ScrapeCount = 1000,
    [double]$RequestDelay = 0.25,
    [int]$TimeoutSeconds = 60,
    [int]$MaxRetries = 5,
    [string]$UserAgent = "",
    [switch]$DiscoverCollections,
    [switch]$NoDiscoverCollections,
    [int]$CollectionDepth = 1,
    [int]$MaxCollections = 0,
    [switch]$RetryFailed,
    [switch]$JsonLines,
    [switch]$Debug,
    [switch]$NoServer,
    [switch]$KeepServerRunning,
    [switch]$CreateAdmin,
    [string]$AdminUsername = "admin",
    [string]$AdminPassword = "",
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"

function Resolve-Python {
    param([string]$ConfiguredPython)
    if ($ConfiguredPython) {
        if (Test-Path -LiteralPath $ConfiguredPython) {
            return (Resolve-Path -LiteralPath $ConfiguredPython).Path
        }
        $configuredCommand = Get-Command $ConfiguredPython -ErrorAction SilentlyContinue
        if ($configuredCommand) {
            return $configuredCommand.Source
        }
        throw "Configured Python was not found: $ConfiguredPython"
    }

    $runtimePython = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
    if (Test-Path -LiteralPath $runtimePython) {
        return $runtimePython
    }

    $candidate = Get-Command python -ErrorAction SilentlyContinue
    if ($candidate) {
        return $candidate.Source
    }

    $candidate = Get-Command py -ErrorAction SilentlyContinue
    if ($candidate) {
        return $candidate.Source
    }

    throw "Could not find Python. Pass -Python C:\Path\To\python.exe."
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$pythonExe = Resolve-Python -ConfiguredPython $Python
$runner = Join-Path $repoRoot "scripts\windows_local_ia_discovery.py"
$dataPath = $DataDir
if (-not [System.IO.Path]::IsPathRooted($dataPath)) {
    $dataPath = Join-Path $repoRoot $DataDir
}

$runnerArgs = @(
    "-B",
    $runner,
    "--data-dir",
    ([System.IO.Path]::GetFullPath($dataPath)),
    "--host",
    $HostName,
    "--port",
    [string]$Port,
    "--port-scan-count",
    [string]$PortScanCount,
    "--collection",
    $Collection,
    "--scrape-count",
    [string]$ScrapeCount,
    "--request-delay",
    [string]$RequestDelay,
    "--timeout",
    [string]$TimeoutSeconds,
    "--max-retries",
    [string]$MaxRetries
)

if ($Query) {
    $runnerArgs += @("--query", $Query)
}
if ($CrawlName) {
    $runnerArgs += @("--crawl-name", $CrawlName)
}
if ($MaxItems -gt 0) {
    $runnerArgs += @("--max-items", [string]$MaxItems)
}
if ($UserAgent) {
    $runnerArgs += @("--user-agent", $UserAgent)
}
if ($NoDiscoverCollections) {
    $runnerArgs += @("--no-discover-collections", "--collection-depth", [string]$CollectionDepth)
} elseif ($DiscoverCollections) {
    $runnerArgs += @("--discover-collections", "--collection-depth", [string]$CollectionDepth)
} else {
    $runnerArgs += @("--collection-depth", [string]$CollectionDepth)
}
if ($MaxCollections -gt 0) {
    $runnerArgs += @("--max-collections", [string]$MaxCollections)
}
if ($RetryFailed) {
    $runnerArgs += "--retry-failed"
}
if ($JsonLines) {
    $runnerArgs += "--jsonl"
}
if ($Debug) {
    $runnerArgs += "--debug"
}
if ($NoServer) {
    $runnerArgs += "--no-server"
}
if ($KeepServerRunning) {
    $runnerArgs += "--keep-server-running"
}
if ($CreateAdmin) {
    $runnerArgs += @("--create-admin", "--admin-username", $AdminUsername)
    if ($AdminPassword) {
        $runnerArgs += @("--admin-password", $AdminPassword)
    }
}
if ($CheckOnly) {
    $runnerArgs += "--check-only"
}

& $pythonExe @runnerArgs
exit $LASTEXITCODE

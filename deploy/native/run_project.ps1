<#
.SYNOPSIS
    Start, stop and inspect the ASP native deployment on Windows.

.DESCRIPTION
    Runs the whole stack as ordinary Windows processes instead of containers,
    for hosts where Docker is unavailable. PostgreSQL and nginx manage their own
    lifecycle; every other process is tracked through logs\.pids.

    Runtime binaries and data live under $AspHome, kept outside the repository.
#>
param(
    [ValidateSet("all", "infra", "backend", "web")]
    [string]$Service = "all",
    [switch]$Stop,
    [switch]$Status
)

$ErrorActionPreference = "Stop"

$AspHome = if ($env:ASP_HOME) { $env:ASP_HOME } else { "C:\Users\trongtd\asp" }
$Repo    = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
$Backend = Join-Path $Repo "backend"
$Python  = Join-Path $Backend ".venv\Scripts\python.exe"
$LogDir  = Join-Path $AspHome "logs"
$PidFile = Join-Path $LogDir ".pids"
$PgData  = Join-Path $AspHome "data\pgdata"

# Worker processes. Comment out any worker whose integration is not configured
# yet; each one costs roughly 150-250 MB of RAM.
$Workers = @(
    "run_agentic_module_worker",
    "run_agentic_case_analysis_worker",
    "run_agentic_playbook_worker",
    "run_notification_worker",
    "run_qradar_offense_worker",
    "run_dashboard_cache_worker",
    "run_elk_action_worker",
    "run_trellix_detection_worker",
    "run_agentic_correlation_worker"
)

function Log-Info  { param($msg) Write-Host "[INFO]  $msg" -ForegroundColor Green  }
function Log-Warn  { param($msg) Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Log-Error { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red    }

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

function Invoke-RotateLogs {
    $cutoff  = (Get-Date).AddDays(-7)
    $deleted = 0
    Get-ChildItem -Path $LogDir -Filter "*.log" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        ForEach-Object { Remove-Item $_.FullName -Force; $deleted++ }
    if ($deleted -gt 0) { Log-Info "Log rotation: removed $deleted file(s) older than 7 days." }
}

function Get-TrackedPids {
    if (-not (Test-Path $PidFile)) { return @{} }
    $map = @{}
    Get-Content $PidFile | Where-Object { $_ -match "=" } | ForEach-Object {
        $parts = $_ -split "=", 2
        $map[$parts[0]] = [int]$parts[1]
    }
    return $map
}

function Start-Tracked {
    param([string]$Name, [string]$FilePath, [string[]]$Arguments, [string]$WorkDir)
    $proc = Start-Process -FilePath $FilePath `
        -ArgumentList $Arguments `
        -WorkingDirectory $WorkDir `
        -RedirectStandardOutput (Join-Path $LogDir "$Name.log") `
        -RedirectStandardError  (Join-Path $LogDir "${Name}_err.log") `
        -WindowStyle Hidden `
        -PassThru
    Log-Info "$Name started [PID $($proc.Id)]"
    return $proc.Id
}

function Test-Postgres {
    & "$AspHome\vendor\pgsql\bin\pg_isready.exe" -h 127.0.0.1 -p 5432 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Start-Postgres {
    if (Test-Postgres) { Log-Info "postgres already accepting connections"; return }
    # Fire and forget, then poll. Neither a pipeline nor -Wait can be used here:
    # postgres inherits pg_ctl's handles and outlives it, so both would block
    # until the database server itself shuts down.
    Start-Process -FilePath "$AspHome\vendor\pgsql\bin\pg_ctl.exe" `
        -ArgumentList @("-D", $PgData, "-l", (Join-Path $LogDir "postgres\pg_ctl.log"), "start") `
        -WindowStyle Hidden | Out-Null
    foreach ($attempt in 1..30) {
        Start-Sleep -Seconds 1
        if (Test-Postgres) { Log-Info "postgres started"; return }
    }
    Log-Error "postgres did not become ready - see $LogDir\postgres\pg_ctl.log"
}

function Stop-Postgres {
    if (-not (Test-Path $PgData)) { return }
    Start-Process -FilePath "$AspHome\vendor\pgsql\bin\pg_ctl.exe" `
        -ArgumentList @("-D", $PgData, "-m", "fast", "-w", "stop") `
        -WindowStyle Hidden -Wait | Out-Null
    Log-Info "postgres stopped"
}

function Start-Nginx {
    if (Get-Process nginx -ErrorAction SilentlyContinue) { Log-Info "nginx already running"; return }
    # nginx runs in the foreground on Windows, so it must be detached explicitly.
    Start-Process -FilePath "$AspHome\vendor\nginx\nginx.exe" `
        -ArgumentList @("-p", "$AspHome/", "-c", "$AspHome/nginx.conf") `
        -WorkingDirectory "$AspHome\vendor\nginx" `
        -WindowStyle Hidden | Out-Null
    Start-Sleep -Seconds 2
    if (Get-Process nginx -ErrorAction SilentlyContinue) {
        Log-Info "nginx started on https://localhost"
    } else {
        Log-Error "nginx failed to start - see $LogDir\nginx\error.log"
    }
}

function Stop-Nginx {
    if (-not (Get-Process nginx -ErrorAction SilentlyContinue)) { return }
    & "$AspHome\vendor\nginx\nginx.exe" -p "$AspHome/" -c "$AspHome/nginx.conf" -s stop 2>&1 | Out-Null
    Start-Sleep -Seconds 1
    Get-Process nginx -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Log-Info "nginx stopped"
}

function Invoke-Stop {
    Stop-Nginx
    $tracked = Get-TrackedPids
    foreach ($name in $tracked.Keys) {
        $id = $tracked[$name]
        # The venv python.exe is a trampoline: the real interpreter runs as its
        # child, so the whole tree has to go or workers survive as orphans.
        if (Get-Process -Id $id -ErrorAction SilentlyContinue) {
            & taskkill.exe /PID $id /T /F 2>&1 | Out-Null
            Log-Info "Stopped $name (PID $id and children)"
        } else {
            Log-Warn "Could not stop $name (PID $id) - already exited?"
        }
    }
    if (Test-Path $PidFile) { Remove-Item $PidFile -Force }
    Stop-Postgres
    Log-Info "All services stopped."
}

function Invoke-Status {
    $pgReady = & "$AspHome\vendor\pgsql\bin\pg_isready.exe" -h 127.0.0.1 -p 5432 2>&1
    "{0,-32} {1}" -f "postgres", $(if ($LASTEXITCODE -eq 0) { "up" } else { "down" })
    "{0,-32} {1}" -f "nginx", $(if (Get-Process nginx -ErrorAction SilentlyContinue) { "up" } else { "down" })
    $tracked = Get-TrackedPids
    if ($tracked.Count -eq 0) { Log-Warn "No PID file - tracked services look stopped."; return }
    foreach ($name in ($tracked.Keys | Sort-Object)) {
        $proc = Get-Process -Id $tracked[$name] -ErrorAction SilentlyContinue
        if ($proc) {
            # Report the tree, because the tracked PID is only the venv trampoline.
            $ids = @($proc.Id) + (Get-CimInstance Win32_Process -Filter "ParentProcessId=$($proc.Id)" |
                                  Select-Object -ExpandProperty ProcessId)
            $mb = (Get-Process -Id $ids -ErrorAction SilentlyContinue |
                   Measure-Object WorkingSet64 -Sum).Sum / 1MB
            "{0,-32} up    PID {1,-7} {2,6:N0} MB" -f $name, $proc.Id, $mb
        } else {
            "{0,-32} down  (stale PID {1})" -f $name, $tracked[$name]
        }
    }
}

if ($Status) { Invoke-Status; exit 0 }
if ($Stop)   { Invoke-Stop;   exit 0 }

if (-not (Test-Path (Join-Path $Backend ".env"))) {
    Log-Error "backend\.env not found. Run the native bootstrap first."
    exit 1
}

Invoke-RotateLogs

Write-Host ""
Write-Host "  ASP - Starting native stack" -ForegroundColor Cyan
Write-Host ""

$StartedPids = Get-TrackedPids

if ($Service -in "all", "infra") {
    Start-Postgres
    if (-not (Get-Process redis-server -ErrorAction SilentlyContinue)) {
        $StartedPids["redis"] = Start-Tracked -Name "redis" `
            -FilePath "$AspHome\vendor\redis\redis-server.exe" `
            -Arguments @([char]47 + "redis.conf") `
            -WorkDir "$AspHome\vendor\redis"
    } else {
        Log-Info "redis already running"
    }
}

if ($Service -in "all", "backend") {
    $StartedPids["asgi"] = Start-Tracked -Name "asgi" `
        -FilePath $Python `
        -Arguments @("-m", "uvicorn", "asp.asgi:application", "--host", "127.0.0.1", "--port", "8001") `
        -WorkDir $Backend

    foreach ($worker in $Workers) {
        $short = $worker -replace "^run_", "" -replace "_worker$", ""
        $StartedPids[$short] = Start-Tracked -Name $short `
            -FilePath $Python `
            -Arguments @("manage.py", $worker) `
            -WorkDir $Backend
    }
}

if ($Service -in "all", "web") { Start-Nginx }

$StartedPids.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" } | Set-Content $PidFile

Write-Host ""
Write-Host "  ASP       -> https://localhost/" -ForegroundColor Cyan
Write-Host "  API docs  -> https://localhost/api/docs/" -ForegroundColor Cyan
Write-Host "  Logs      -> $LogDir" -ForegroundColor Gray
Write-Host "  Status    -> .\deploy\native\run_project.ps1 -Status" -ForegroundColor Gray
Write-Host "  To stop   -> .\deploy\native\run_project.ps1 -Stop" -ForegroundColor Gray
Write-Host ""

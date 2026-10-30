param(
    [Parameter(Mandatory = $true)]
    [string]$ServerHost,
    [Parameter(Mandatory = $true)]
    [string]$Username,
    [System.Security.SecureString]$Password,
    [string]$Executable = (Join-Path $PSScriptRoot '../target/release/rsexec.exe')
)
$ErrorActionPreference = 'Stop'
if (-not $Password) { $Password = Read-Host 'Lab password' -AsSecureString }
$labPlaintext = [pscredential]::new($Username, $Password).GetNetworkCredential().Password
$labId = [guid]::NewGuid().ToString('N').Substring(0, 10)
$labPrefix = "RustExecLab_$labId"
$labServices = [System.Collections.Generic.List[string]]::new()
$labResults = [System.Collections.Generic.List[object]]::new()
$labExe = (Resolve-Path -LiteralPath $Executable).Path
$reportDir = Join-Path $PSScriptRoot '../lab-output'
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
function Invoke-LabCase {
    param([string]$Label, [string[]]$CommandArgs, [string]$InputText = '', [Nullable[int]]$ExpectedExit = 0, [string]$StdoutPattern, [string]$StderrPattern)
    $serviceName = "${labPrefix}_$Label"
    $labServices.Add($serviceName)
    $start = [System.Diagnostics.ProcessStartInfo]::new($labExe)
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    foreach ($argument in @("\\$ServerHost", '-u', $Username, '-p', $labPlaintext, '-n', '15', '-r', $serviceName) + $CommandArgs) { $start.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::Start($start)
    $outTask = $process.StandardOutput.ReadToEndAsync()
    $errTask = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Write($InputText)
    $process.StandardInput.Close()
    if (-not $process.WaitForExit(45000)) { $process.Kill(); throw "Case $Label timed out; service $serviceName needs inspection" }
    $outText = $outTask.GetAwaiter().GetResult()
    $errText = $errTask.GetAwaiter().GetResult()
    $exitCode = $process.ExitCode
    $process.Dispose()
    $case = [pscustomobject]@{ case = $Label; service = $serviceName; exitCode = $exitCode; stdout = $outText; stderr = $errText }
    $labResults.Add($case)
    if ($null -ne $ExpectedExit -and $exitCode -ne $ExpectedExit) { throw "Case $Label returned $exitCode; expected $ExpectedExit. $errText" }
    if ($StdoutPattern -and $outText -notmatch $StdoutPattern) { throw "Case $Label stdout did not match expectation: $outText" }
    if ($StderrPattern -and $errText -notmatch $StderrPattern) { throw "Case $Label stderr did not match expectation: $errText" }
    Write-Host "PASS $Label (exit $exitCode; stdout $($outText.Length) chars; stderr $($errText.Length) chars)"
    return $case
}
try {
    Invoke-LabCase Identity @('cmd.exe', '/d', '/q', '/c', 'hostname & whoami & exit /b 37') -ExpectedExit 37 -StdoutPattern '(?is)\S+\r\n.+' | Out-Null
    Invoke-LabCase System @('-s', 'cmd.exe', '/d', '/q', '/c', 'whoami /user & exit /b 42') -ExpectedExit 42 -StdoutPattern '(?is)nt authority\\system.*S-1-5-18' | Out-Null
    Invoke-LabCase Streams @('cmd.exe', '/d', '/q', '/c', 'echo OUT_MARK & echo ERR_MARK 1>&2 & exit /b 23') -ExpectedExit 23 -StdoutPattern 'OUT_MARK' -StderrPattern 'ERR_MARK' | Out-Null
    Invoke-LabCase Stdin @('sort.exe') -InputText "zebra`r`nalpha`r`n" -StdoutPattern '(?s)alpha.*zebra' | Out-Null
    Invoke-LabCase Workdir @('-w', 'C:\Windows\Temp', 'cmd.exe', '/d', '/q', '/c', 'cd') -StdoutPattern 'C:\\Windows\\Temp' | Out-Null
    Invoke-LabCase Settings @('-a', '1', '-belownormal', 'powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '$p=[Diagnostics.Process]::GetCurrentProcess(); "PRIORITY=$($p.PriorityClass)"; "AFFINITY=$($p.ProcessorAffinity)"') -StdoutPattern '(?s)PRIORITY=BelowNormal.*AFFINITY=1' | Out-Null
    Invoke-LabCase LargeOutput @('powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '1..12000 | ForEach-Object { "row_{0:D5}" -f $_ }') -StdoutPattern 'row_12000' | Out-Null
    $copySource = Join-Path (Split-Path -Parent $labExe) "rsexec lab probe $labId.exe"
    Copy-Item -LiteralPath $labExe -Destination $copySource
    try {
        Invoke-LabCase Copy @('-c', $copySource, '--version') -StdoutPattern 'rsexec 0\.1\.0' | Out-Null
    } finally {
        try { Invoke-LabCase CopyCleanup @('-s', 'cmd.exe', '/d', '/q', '/c', "del /q `"C:\Windows\rsexec lab probe $labId.exe`"") | Out-Null }
        finally { Remove-Item -LiteralPath $copySource }
    }
    $marker = "C:\Windows\Temp\RustExecLab_$labId.txt"
    $detached = Invoke-LabCase Detached @('-s', '-d', 'cmd.exe', '/d', '/q', '/c', "echo DETACHED_OK > $marker") -ExpectedExit $null -StderrPattern 'Process \d+ started'
    $pidMatch = [regex]::Match($detached.stderr, 'Process (\d+) started')
    if ($detached.exitCode -ne [int]$pidMatch.Groups[1].Value) { throw 'Detached exit code differs from the reported PID' }
    Invoke-LabCase DetachedRead @('-s', 'cmd.exe', '/d', '/q', '/c', "type $marker & del /q $marker") -StdoutPattern 'DETACHED_OK' | Out-Null
    $env:RSEXEC_TEST_HOST = $ServerHost
    $env:RSEXEC_TEST_USER = $Username
    $env:RSEXEC_TEST_PASSWORD = $labPlaintext
    $previousServices = @(Get-ChildItem -LiteralPath $reportDir -Filter 'lab-results-*.json' -ErrorAction SilentlyContinue | ForEach-Object { (Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json).serviceNames })
    $env:RSEXEC_TEST_SERVICES = (@($labServices) + $previousServices | Sort-Object -Unique) -join ','
    & cargo test --offline authorized_lab_cleanup -- --ignored --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'Lab cleanup verification failed' }
    Write-Host 'PASS remote service and artifact cleanup'
} finally {
    $report = [pscustomobject]@{ runId = $labId; tests = $labResults; serviceNames = $labServices }
    $report | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $reportDir 'lab-results.json')
    $report | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $reportDir "lab-results-$labId.json")
    foreach ($name in @('RSEXEC_TEST_HOST', 'RSEXEC_TEST_USER', 'RSEXEC_TEST_PASSWORD', 'RSEXEC_TEST_SERVICES')) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
    $labPlaintext = $null
}

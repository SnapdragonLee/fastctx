param([string]$Mode = 'test', [int]$VictimId = 0, [string]$Marker, [string]$Result, [string]$Ready)
$ErrorActionPreference = 'Stop'
if ($Mode -eq 'victim') {
    [IO.File]::WriteAllText($Ready, [string]$PID)
    Start-Sleep -Seconds 180
    exit
}
$probe = @'
using System;
using System.Runtime.InteropServices;
public static class ProcessProbe {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr process, int kind, IntPtr buffer, int length, out int needed);
    // ProcessCommandLineInformation (60) needs only PROCESS_QUERY_LIMITED_INFORMATION.
    public static string CommandLine(uint pid, out int openError, out int status) {
        status = 0;
        IntPtr process = OpenProcess(0x1000, false, pid);
        openError = process == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
        if (process == IntPtr.Zero) return null;
        try {
            int needed;
            NtQueryInformationProcess(process, 60, IntPtr.Zero, 0, out needed);
            if (needed <= 0) { status = -1; return null; }
            IntPtr buffer = Marshal.AllocHGlobal(needed);
            try {
                status = NtQueryInformationProcess(process, 60, buffer, needed, out needed);
                if (status != 0) return null;
                int bytes = (ushort)Marshal.ReadInt16(buffer);
                return Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, IntPtr.Size), bytes / 2);
            } finally { Marshal.FreeHGlobal(buffer); }
        } finally { CloseHandle(process); }
    }
}
'@
if ($Mode -eq 'reader') {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$VictimId"
    $text = [string]$process.CommandLine
    Add-Type $probe
    $openError = 0; $status = 0
    $native = [ProcessProbe]::CommandLine([uint32]$VictimId, [ref]$openError, [ref]$status)
    $handle = [ProcessProbe]::OpenProcess(0x0410, $false, $VictimId)
    $memoryError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $memoryOpened = $handle -ne [IntPtr]::Zero
    if ($memoryOpened) { [void][ProcessProbe]::CloseHandle($handle) }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $facts = @{ reader=$identity.User.Value; administrator=$admin; wmiCommandLine=$text; limitedOpenError=$openError;
                nativeStatus=$status; nativeCommandLine=$native; memoryReadOpened=$memoryOpened; memoryReadError=$memoryError }
    [IO.File]::WriteAllText($Result, ($facts | ConvertTo-Json))
    $leaked = $text.Contains($Marker) -or ($null -ne $native -and $native.Contains($Marker))
    if ($admin -or $leaked -or $memoryOpened -or $memoryError -ne 5) { exit 1 }
    exit 0
}
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Run only on a disposable GitHub Windows runner.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required to create the test accounts.' }
$root = Join-Path $env:ProgramData ('fastctx-boundary-' + [Guid]::NewGuid().ToString('N'))
$names = @()
$victim = $null
$reader = $null
try {
    New-Item -ItemType Directory -Path $root | Out-Null
    & icacls $root /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
    if ($LASTEXITCODE) { throw 'Cannot prepare shared test fixture.' }
    $script = Join-Path $root 'probe.ps1'
    Copy-Item $PSCommandPath $script
    $credentials = @()
    foreach ($i in 1..2) {
        $name = 'fxg' + [Guid]::NewGuid().ToString('N').Substring(0,10)
        $password = 'Fx!' + [Guid]::NewGuid().ToString('N') + '7a'
        $secure = ConvertTo-SecureString $password -AsPlainText -Force
        New-LocalUser -Name $name -Password $secure -AccountNeverExpires | Out-Null
        $names += $name
        $users = Get-LocalGroup -SID 'S-1-5-32-545'
        Add-LocalGroupMember -Group $users -Member $name
        $credentials += [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$name", $secure)
    }
    $marker = 'private-argument-' + [Guid]::NewGuid().ToString('N')
    $ready = Join-Path $root 'pid.txt'
    $result = Join-Path $root 'result.json'
    $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $victim = Start-Process $shell -Credential $credentials[0] -WorkingDirectory $root -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$script`"",'-Mode','victim','-Marker',$marker,'-Ready',"`"$ready`"")
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path $ready)) {
        if ($victim.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'Victim did not start.' }
        Start-Sleep -Milliseconds 100
    }
    $victimId = [int](Get-Content $ready)
    $control = Get-CimInstance Win32_Process -Filter "ProcessId=$victimId"
    if (-not ([string]$control.CommandLine).Contains($marker)) { throw 'Administrator positive control did not see the private argument.' }
    Add-Type $probe
    $openError = 0; $status = 0
    $native = [ProcessProbe]::CommandLine([uint32]$victimId, [ref]$openError, [ref]$status)
    if ($null -eq $native -or -not $native.Contains($marker)) { throw "Administrator positive control could not read the arguments natively ($openError, $status)." }
    $reader = Start-Process $shell -Credential $credentials[1] -WorkingDirectory $root -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$script`"",'-Mode','reader','-VictimId',$victimId,'-Marker',$marker,'-Result',"`"$result`"")
    if (-not $reader.WaitForExit(30000)) { throw 'Reader timed out.' }
    if (Test-Path $result) { Get-Content $result }
    if ($reader.ExitCode -ne 0 -or -not (Test-Path $result)) { throw 'The second ordinary account boundary failed.' }
    Write-Output 'PASS Windows: administrator reads the fixture; a second ordinary account cannot.'
} finally {
    foreach ($process in @($reader,$victim)) {
        if ($null -ne $process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force }
    }
    foreach ($name in $names) { Remove-LocalUser -Name $name }
    if (Test-Path $root) { Remove-Item -Recurse -Force $root }
}

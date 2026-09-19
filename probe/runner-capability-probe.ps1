# Runner capability probe Ã¢â‚¬â€ isolated fixture, no repo source, no install.
#
# Distinguishes two hypotheses for the two failing codex-windows-sandbox legacy tests:
#   A. capability-SID ACL identity: a custom SID's inheritable allow ACE is not honored by a
#      WRITE_RESTRICTED restricted token on this runner (would reproduce the delete-test denial).
#   B. parent job object / process tree: a descendant process does not survive its parent's exit
#      on this runner (would reproduce the descendant-survival failure).
#
# It prints a JSON summary. It only touches %TEMP% and reads the current process token.

$ErrorActionPreference = 'Continue'
$result = [ordered]@{
  env = [ordered]@{}
  aclIdentity = [ordered]@{}
  processTree = [ordered]@{}
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class ProbeNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES { public IntPtr Sid; public int Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public int cb;
        public IntPtr lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CreateRestrictedToken(IntPtr ExistingTokenHandle, int Flags,
        int DisableSidCount, IntPtr SidsToDisable, int DeletePrivilegeCount, IntPtr PrivilegesToDelete,
        int RestrictedSidCount, IntPtr SidsToRestrict, out IntPtr NewTokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags,
        string lpApplicationName, string lpCommandLine, int dwCreationFlags, IntPtr lpEnvironment,
        string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out int lpExitCode);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsProcessInJob(IntPtr ProcessHandle, IntPtr JobHandle, out bool Result);
}
'@

$result.env.whoami = (whoami) 2>&1 | Out-String
$result.env.psVersion = $PSVersionTable.PSVersion.ToString()
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $result.env.isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $result.env.isAdmin = "error: $($_.Exception.Message)" }

$inJob = $false
try {
    $current = [System.Diagnostics.Process]::GetCurrentProcess().Handle
    $ok = [ProbeNative]::IsProcessInJob($current, [IntPtr]::Zero, [ref]$inJob)
    $result.env.isProcessInAnyJob = $ok
    $result.env.isInJobValue = $inJob
} catch {
    $result.env.isProcessInAnyJob = "error: $($_.Exception.Message)"
}

# ---- Probe A: capability-SID ACL identity under a WRITE_RESTRICTED token -------------------------
try {
    $base = Join-Path $env:TEMP ("aclid-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $base | Out-Null
    $grantFile = Join-Path $base 'grant.txt'
    $controlFile = Join-Path $base 'control.txt'
    Set-Content -LiteralPath $grantFile -Value 'grant'
    Set-Content -LiteralPath $controlFile -Value 'control'

    $sidStr = 'S-1-5-21-{0}-{1}-{2}-{3}' -f (Get-Random -Minimum 100000 -Maximum 2147483000),
        (Get-Random -Minimum 100000 -Maximum 2147483000), (Get-Random -Minimum 100000 -Maximum 2147483000),
        (Get-Random -Minimum 100000 -Maximum 2147483000)
    $sid = New-Object Security.Principal.SecurityIdentifier($sidStr)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $sid, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl = Get-Acl -LiteralPath $base
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $base -AclObject $acl
    $result.aclIdentity.sid = $sidStr
    $result.aclIdentity.dirAce = @((Get-Acl -LiteralPath $base).Access |
        Where-Object { $_.IdentityReference -eq $sid } |
        ForEach-Object { "$($_.FileSystemRights)|inherited=$($_.IsInherited)|flags=$($_.InheritanceFlags)" })
    $result.aclIdentity.childInherited = @((Get-Acl -LiteralPath $grantFile).Access |
        Where-Object { $_.IdentityReference -eq $sid } |
        ForEach-Object { "$($_.FileSystemRights)|inherited=$($_.IsInherited)|flags=$($_.InheritanceFlags)" })

    # Control: current token deletes its own file.
    & "$env:SystemRoot\System32\cmd.exe" /d /c "del /f /q `"$controlFile`"" | Out-Null
    $result.aclIdentity.controlDeleted = -not (Test-Path -LiteralPath $controlFile)

    # Restricted token: restrict to the custom SID + Everyone + logon SID, write-restricted.
    $hToken = [IntPtr]::Zero
    $tokenOk = [ProbeNative]::OpenProcessToken(
        [System.Diagnostics.Process]::GetCurrentProcess().Handle, 0xF01FF, [ref]$hToken)
    if (-not $tokenOk) {
        $result.aclIdentity.error = "OpenProcessToken failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    } else {
        $sidBytes = New-Object byte[] $sid.BinaryLength
        $sid.GetBinaryForm($sidBytes, 0)
        $sidBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal($sidBytes.Length)
        [Runtime.InteropServices.Marshal]::Copy($sidBytes, 0, $sidBuf, $sidBytes.Length)

        $everyone = New-Object Security.Principal.SecurityIdentifier(
            [Security.Principal.WellKnownSidType]::WorldSid, $null)
        $everyoneBytes = New-Object byte[] $everyone.BinaryLength
        $everyone.GetBinaryForm($everyoneBytes, 0)
        $everyoneBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal($everyoneBytes.Length)
        [Runtime.InteropServices.Marshal]::Copy($everyoneBytes, 0, $everyoneBuf, $everyoneBytes.Length)

        $entrySize = [Runtime.InteropServices.Marshal]::SizeOf([type][ProbeNative+SID_AND_ATTRIBUTES])
        $entriesBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal($entrySize * 2)
        $e1 = [ProbeNative+SID_AND_ATTRIBUTES]::new()
        $e1.Sid = $sidBuf; $e1.Attributes = 0
        [Runtime.InteropServices.Marshal]::StructureToPtr($e1, $entriesBuf, $false)
        $e2 = [ProbeNative+SID_AND_ATTRIBUTES]::new()
        $e2.Sid = $everyoneBuf; $e2.Attributes = 0
        [Runtime.InteropServices.Marshal]::StructureToPtr($e2, [IntPtr]::Add($entriesBuf, $entrySize), $false)

        $flags = 0x1 -bor 0x4 -bor 0x8  # DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED
        $newToken = [IntPtr]::Zero
        $restricted = [ProbeNative]::CreateRestrictedToken(
            $hToken, $flags, 0, [IntPtr]::Zero, 0, [IntPtr]::Zero, 2, $entriesBuf, [ref]$newToken)
        if (-not $restricted) {
            $result.aclIdentity.error = "CreateRestrictedToken failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        } else {
            $si = [ProbeNative+STARTUPINFO]::new()
            $si.cb = [Runtime.InteropServices.Marshal]::SizeOf([type][ProbeNative+STARTUPINFO])
            $pi = [ProbeNative+PROCESS_INFORMATION]::new()
            $cmdLine = "/d /c del /f /q `"$grantFile`""
            $spawned = [ProbeNative]::CreateProcessWithTokenW(
                $newToken, 0, "$env:SystemRoot\System32\cmd.exe", $cmdLine, 0x08000000,
                [IntPtr]::Zero, $null, [ref]$si, [ref]$pi)
            if (-not $spawned) {
                $result.aclIdentity.error = "CreateProcessWithTokenW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            } else {
                [void][ProbeNative]::WaitForSingleObject($pi.hProcess, 10000)
                $exitCode = 0
                [void][ProbeNative]::GetExitCodeProcess($pi.hProcess, [ref]$exitCode)
                $result.aclIdentity.childExitCode = $exitCode
                $result.aclIdentity.grantedFileDeleted = -not (Test-Path -LiteralPath $grantFile)
                [void][ProbeNative]::CloseHandle($pi.hProcess)
                [void][ProbeNative]::CloseHandle($pi.hThread)
            }
            [void][ProbeNative]::CloseHandle($newToken)
        }
        [void][ProbeNative]::CloseHandle($hToken)
    }
} catch {
    $result.aclIdentity.error = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
}

# ---- Probe B: does a descendant survive its parent's exit on this runner? ------------------------
try {
    $pwsh = (Get-Process -Id $PID).Path
    $marker = Join-Path $env:TEMP ("survive-" + [guid]::NewGuid().ToString('N') + ".txt")
    $inner = Join-Path $env:TEMP ("inner-" + [guid]::NewGuid().ToString('N') + ".ps1")
    $outer = Join-Path $env:TEMP ("outer-" + [guid]::NewGuid().ToString('N') + ".ps1")
    Set-Content -LiteralPath $inner -Value "Start-Sleep -Seconds 2; Set-Content -LiteralPath '$marker' -Value 'alive'; Start-Sleep -Seconds 20"
    Set-Content -LiteralPath $outer -Value "Start-Process -FilePath '$pwsh' -ArgumentList '-NoProfile','-File','$inner' -WindowStyle Hidden; Start-Sleep -Seconds 1"
    & $pwsh -NoProfile -File $outer | Out-Null
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $marker)) {
        Start-Sleep -Milliseconds 250
    }
    $result.processTree.descendantSurvived = Test-Path -LiteralPath $marker
    $result.processTree.markerPath = $marker
} catch {
    $result.processTree.error = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
}

$result | ConvertTo-Json -Depth 6

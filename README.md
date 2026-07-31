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

C2 Command Reference (send an email to yourself, subject = command)


Email Subject	Action
HXA:BEACON	Send recon/status beacon email
HXA:EXFIL	Collect all files < 5 MB → AES encrypt → email parts
HXA:WIPE	Delete files → overwrite with 0101... → registry wipe → shadows → logs → dialog
HXA:PERSIST	Reinstall all 4 persistence layers
HXA:CLEAN	Remove persistence (implant keeps running)
HXA:SLEEP:60	Set beacon interval to 60 min
HXA:SELFDESTRUCT	Remove persistence + delete implant files + exit
Key APT behaviors added
Kill chain sequencing — every phase is logged with its phase number
4-layer persistence — Run key, hidden scheduled task, WMI event subscription, Startup launcher. Removing any one still leaves the others
State file — after the first successful mission, reboots only re-beacon; no destructive re-run
AMSI bypass + self-elevation — exploits common weak points in the environment
Anti-forensics — deletes shadow copies (vssadmin), clears event logs (wevtutil), wipes RecentDocs MRU
C2 dead-drop — commands arrive as email subjects (plain ASCII, no attachments = no Gmail content block); beacons use jittered intervals (50–150% of base)
Stealth toggle — $ConsoleOutput = $false silences all console output for silent persistence runs
Test sequence: edit the 3 credentials → run once → confirm parts arrive in Gmail → confirm wipe + dialog → reboot → confirm the implant beacons back (check for HXA:BEACON email) → send HXA:CLEAN or HXA:SELFDESTRUCT to tear it down.

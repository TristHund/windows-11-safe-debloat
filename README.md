# Windows 11 Safe Debloat

A security-focused Windows 11 debloating script that removes unnecessary bloatware while preserving system integrity, Windows Defender, and critical Windows Update functionality.

## Security First Approach

## What It Removes

- Non-essential Microsoft Store apps (News, Weather, etc.)
- Unnecessary pre-installed applications
- Optional features like Internet Explorer
- Sponsored content and suggestions
- Non-critical background services
- Tablet PC components (if not needed)

## What it maintains:
- Windows Defender and security components
- Windows Update functionality
- Keeps system serviceability intact
- Creates System Restore points
- Logs all operations for review
- Verifies system integrity after modifications

## 📋 Prerequisites

- Windows 11 (any edition)
- Administrator privileges
- PowerShell 5.1 or later

## Usage

1. Download `safe-debloat.ps1`
2. Right-click and select "Run with PowerShell"
3. If prompted, enter `Y` to confirm execution
4. Wait for the script to complete
5. Restart your computer

```powershell
# Or run from PowerShell Admin prompt:
Set-ExecutionPolicy Bypass -Scope Process -Force
.\safe-debloat.ps1
```

## Logging

The script creates detailed logs at:
`%USERPROFILE%\Desktop\DebloatLog_[DateTime].txt`

## Post-Installation Verification

After running the script and restarting:
1. Verify Windows Security is functioning
2. Check Windows Update is working
3. Review the log file for any warnings

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Target = Join-Path $Root "launch_demo_app.bat"
$Desktop = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $Desktop "Security AutoFix Demo.lnk"

$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $Target
$Shortcut.WorkingDirectory = $Root
$Shortcut.IconLocation = "$env:SystemRoot\System32\shell32.dll,13"
$Shortcut.Description = "Launch Security Auto-Fix demo app"
$Shortcut.Save()

Write-Host "Shortcut created: $ShortcutPath"

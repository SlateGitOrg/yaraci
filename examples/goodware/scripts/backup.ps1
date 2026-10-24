# yaraci lab fixture - synthetic and benign
param([string]$Target = 'D:\Backup')
Get-ChildItem -Path $env:USERPROFILE\Documents -Recurse |
  Copy-Item -Destination $Target -Force
Write-Output 'backup complete'

# Build selfdec2.bin with the same ps4-payload-sdk image selfdec used.
#   powershell -File build.ps1
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

docker run --rm --entrypoint sh `
  -v "${here}:/selfdec2" `
  -e PS4SDK=/lib/ps4-payload-sdk `
  -w /selfdec2 `
  ps4-payload-sdk:latest `
  -c "make clean >/dev/null 2>&1; make"

Write-Host ""
Write-Host "built: $here\selfdec2.bin"
Get-ChildItem "$here\selfdec2.bin" | Format-List Name, Length, LastWriteTime


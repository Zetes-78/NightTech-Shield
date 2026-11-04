<#
.SYNOPSIS
  Builds Night Tech Shield and NightTechShield-Setup-<version>.exe, ready to upload.

.EXAMPLE
  .\build.ps1
  Unsigned build for testing on your own PCs.

.EXAMPLE
  .\build.ps1 -SignTool 'signtool sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 /dlib "C:\TrustedSigning\bin\x64\Azure.CodeSigning.Dlib.dll" /dmdf "C:\TrustedSigning\metadata.json"'
  Signed release build. The command gets the file path added to the end.

.NOTES
  Needs: .NET 8 SDK, and Inno Setup 6.3+ (winget install JRSoftware.InnoSetup).
  Change the version in src\NightTech.Shield\NightTech.Shield.csproj before each release.
#>
param(
    [string]$SignTool
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$project = 'src\NightTech.Shield\NightTech.Shield.csproj'
$version = (Select-Xml -Path $project -XPath '//Version').Node.InnerText
Write-Host "Night Tech Shield $version" -ForegroundColor Cyan

# 1. Check the rules
Write-Host 'Running core tests...'
dotnet run --project tests\NightTech.Shield.CoreTests -c Release
if ($LASTEXITCODE -ne 0) { throw 'Core tests failed. Nothing was built.' }

# 2. Publish one self-contained exe
Write-Host 'Publishing...'
if (Test-Path publish) { Remove-Item publish -Recurse -Force }
dotnet publish $project -c Release -o publish
if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }

# 3. Sign the app (optional)
if ($SignTool) {
    Write-Host 'Signing NightTechShield.exe...'
    cmd /c "$SignTool `"$PSScriptRoot\publish\NightTechShield.exe`""
    if ($LASTEXITCODE -ne 0) { throw 'Signing NightTechShield.exe failed.' }
}

# 4. Build the installer
$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 not found. Install it with: winget install JRSoftware.InnoSetup' }

Write-Host 'Building installer...'
$isccArgs = @("/DAppVersion=$version")
if ($SignTool) { $isccArgs += @('/DSign', "/Sntsign=$SignTool `$f") }
& $iscc @isccArgs 'installer\NightTechShield.iss'
if ($LASTEXITCODE -ne 0) { throw 'Installer build failed.' }

# 5. Checksum for the download page
$setup = "dist\NightTechShield-Setup-$version.exe"
$hash = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  NightTechShield-Setup-$version.exe" | Set-Content "$setup.sha256.txt" -Encoding ascii
$sizeMb = [math]::Round((Get-Item $setup).Length / 1MB, 1)

Write-Host ''
Write-Host "Done: $setup ($sizeMb MB)" -ForegroundColor Green
Write-Host "SHA-256: $hash"
if (-not $SignTool) { Write-Host 'Unsigned build: Windows SmartScreen will warn anyone who downloads it.' -ForegroundColor Yellow }

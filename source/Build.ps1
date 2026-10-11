$ErrorActionPreference = 'Stop'
$projectDir = $PSScriptRoot
$packageDir = Split-Path -Parent $projectDir
$goCommand = Get-Command go -ErrorAction Stop
Push-Location (Join-Path $projectDir 'EsurfingGo')
try {
    & $goCommand.Source test . ./network ./utils
    if ($LASTEXITCODE -ne 0) { throw 'Core tests failed' }
    & $goCommand.Source build -trimpath -o (Join-Path $packageDir 'campus-core.exe') .
    if ($LASTEXITCODE -ne 0) { throw 'Core build failed' }
} finally { Pop-Location }
$compilerPath = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$corePath = Join-Path $packageDir 'campus-core.exe'
$sourcePath = Join-Path $projectDir 'CampusLink.cs'
$outputPath = Join-Path $packageDir 'CampusLink.exe'
& $compilerPath /nologo /target:winexe "/out:$outputPath" "/resource:$corePath,campus-core" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.ServiceProcess.dll /reference:System.Security.dll $sourcePath
if ($LASTEXITCODE -ne 0) { throw 'GUI build failed. Close the existing CampusLink window first.' }
Write-Output 'Build completed.'

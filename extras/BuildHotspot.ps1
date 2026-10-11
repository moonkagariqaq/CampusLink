$ErrorActionPreference = 'Stop'
$framework = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319'
$metadata = Join-Path $env:SystemRoot 'System32\WinMetadata'
$runtime = Get-ChildItem (Join-Path $env:SystemRoot 'Microsoft.NET\assembly\GAC_MSIL\System.Runtime') -Recurse -Filter System.Runtime.dll | Select-Object -First 1 -ExpandProperty FullName
$output = Join-Path (Split-Path -Parent $PSScriptRoot) 'CampusHotspotLogon.exe'
& (Join-Path $framework 'csc.exe') /nologo /target:winexe "/out:$output" "/reference:$metadata\Windows.Networking.winmd" "/reference:$metadata\Windows.Foundation.winmd" "/reference:$runtime" /reference:System.Web.Extensions.dll (Join-Path $PSScriptRoot 'CampusHotspotLogon.cs')
if ($LASTEXITCODE -ne 0) { throw 'Hotspot build failed' }

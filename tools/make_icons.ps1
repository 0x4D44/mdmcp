Param(
  [string]$ProjectRoot = (Resolve-Path "$PSScriptRoot\.."),
  [switch]$VerboseLog
)

function Log($msg){ if($VerboseLog){ Write-Host $msg } }

function Ensure-Magick {
  $magick = Get-Command magick -ErrorAction SilentlyContinue
  if(-not $magick){
    Write-Error "ImageMagick 'magick' not found. Install from https://imagemagick.org and ensure it's on PATH."
    exit 1
  }
}

Ensure-Magick

$pairs = @(
  @{ Svg = Join-Path $ProjectRoot 'mdmcpsrvr\res\mdmcpsrvr.svg'; OutDir = Join-Path $ProjectRoot 'mdmcpsrvr\res'; Base='mdmcpsrvr' },
  @{ Svg = Join-Path $ProjectRoot 'mdmcpcfg\res\mdmcpcfg.svg'; OutDir = Join-Path $ProjectRoot 'mdmcpcfg\res'; Base='mdmcpcfg' }
)

foreach($p in $pairs){
  if(-not (Test-Path $p.Svg)){
    Write-Warning "SVG not found: $($p.Svg). Skipping."
    continue
  }
  New-Item -ItemType Directory -Force -Path $p.OutDir | Out-Null
  $sizes = @(16,32,48,64,128,256)
  $pngs = @()
  foreach($s in $sizes){
    $png = Join-Path $p.OutDir ("$($p.Base)-$s.png")
    Log "Rendering $($p.Svg) -> $png ($s x $s)"
    & magick -background none -density 512 "$($p.Svg)" -resize ${s}x${s} "$png"
    if($LASTEXITCODE -ne 0){ throw "magick convert failed for size $s" }
    $pngs += $png
  }
  $ico = Join-Path $p.OutDir ("$($p.Base).ico")
  Log "Assembling ICO -> $ico"
  & magick $pngs "$ico"
  if($LASTEXITCODE -ne 0){ throw "magick ico assemble failed" }
  Write-Host "Created: $ico"
}

Write-Host "Done. Rebuild the workspace to embed icons on Windows."

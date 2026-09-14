# Builds index.html: the gate page with an encrypted copy of src/index.html inside it.
# Local images are inlined first so nothing readable ends up in the repository.
#
#   powershell -ExecutionPolicy Bypass -File protect.ps1 -Password "your password"

param(
  [Parameter(Mandatory = $true)][string]$Password,
  [string]$Source,
  [string]$Template,
  [string]$Output
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Source)   { $Source   = Join-Path $here 'src\index.html' }
if (-not $Template) { $Template = Join-Path $here 'gate.html' }
if (-not $Output)   { $Output   = Join-Path $here 'index.html' }
$srcDir = Split-Path -Parent $Source
$html = [IO.File]::ReadAllText($Source, [Text.Encoding]::UTF8)

# Pack each local image once; the gate page attaches them after unlocking.
# src="assets/x.jpg" becomes data-src="assets/x.jpg" so nothing is requested from the server.
$mime = @{ '.jpg' = 'image/jpeg'; '.jpeg' = 'image/jpeg'; '.png' = 'image/png'; '.webp' = 'image/webp'; '.svg' = 'image/svg+xml' }
$assets = @{}
$html = [regex]::Replace($html, 'src="(assets/[^"]+)"', {
  param($m)
  $path = $m.Groups[1].Value
  $file = Join-Path $srcDir ($path -replace '/', '\')
  $ext = [IO.Path]::GetExtension($file).ToLower()
  if ((Test-Path -LiteralPath $file) -and $mime.ContainsKey($ext)) {
    if (-not $assets.ContainsKey($path)) {
      $assets[$path] = @{ type = $mime[$ext]; data = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file)) }
    }
    return 'data-src="' + $path + '"'
  }
  return $m.Value
})
$html = @{ html = $html; assets = $assets } | ConvertTo-Json -Compress -Depth 4

# PBKDF2 -> 64 bytes: AES-256-CBC key + HMAC-SHA256 key (same scheme the gate page uses)
$iterations = 310000
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$salt = New-Object byte[] 16; $rng.GetBytes($salt)
$iv   = New-Object byte[] 16; $rng.GetBytes($iv)

$kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, $iterations, [Security.Cryptography.HashAlgorithmName]::SHA256)
$keys = $kdf.GetBytes(64)

$aes = [Security.Cryptography.Aes]::Create()
$aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
$aes.Key = [byte[]]$keys[0..31]; $aes.IV = $iv
$plain  = [Text.Encoding]::UTF8.GetBytes($html)
$cipher = $aes.CreateEncryptor().TransformFinalBlock($plain, 0, $plain.Length)

$hmac = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,[byte[]]$keys[32..63])
$mac  = $hmac.ComputeHash([byte[]]($iv + $cipher))

$payload = @{
  iterations = $iterations
  salt = [Convert]::ToBase64String($salt)
  iv   = [Convert]::ToBase64String($iv)
  mac  = [Convert]::ToBase64String($mac)
  data = [Convert]::ToBase64String($cipher)
} | ConvertTo-Json -Compress

$gate = [IO.File]::ReadAllText($Template, [Text.Encoding]::UTF8).Replace('/*__PAYLOAD__*/', $payload)
[IO.File]::WriteAllText($Output, $gate, (New-Object Text.UTF8Encoding $false))

"Wrote $Output ($([math]::Round((Get-Item $Output).Length / 1KB)) KB)"

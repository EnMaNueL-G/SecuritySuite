# _build.ps1 — Compilador SecuritySuite
# Genera icono + EXE con PS2EXE

Set-Location $PSScriptRoot

# Verificar sintaxis antes de compilar
Write-Host "Verificando sintaxis..." -ForegroundColor Cyan
$content = Get-Content ".\SecuritySuite.ps1" -Raw
$errors  = $null
[System.Management.Automation.PSParser]::Tokenize($content, [ref]$errors) | Out-Null
if ($errors.Count -gt 0) {
    Write-Host "ERRORES DE SINTAXIS:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  L$($_.Token.StartLine): $($_.Message)" -ForegroundColor Red }
    exit 1
}
Write-Host "Sintaxis OK (0 errores)" -ForegroundColor Green

# Instalar PS2EXE si no esta disponible
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host "Instalando PS2EXE..." -ForegroundColor Yellow
    Install-Module ps2exe -Scope CurrentUser -Force -AllowClobber
}

# Generar icono (escudo rojo sobre fondo oscuro)
Write-Host "Generando icono..." -ForegroundColor Cyan
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap(48, 48)
$g   = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::FromArgb(10, 10, 26))

# Escudo (forma de escudo con bezier)
$shieldPath = New-Object System.Drawing.Drawing2D.GraphicsPath
$pts = [System.Drawing.PointF[]](
    [System.Drawing.PointF]::new(24, 6),
    [System.Drawing.PointF]::new(8,  12),
    [System.Drawing.PointF]::new(8,  26),
    [System.Drawing.PointF]::new(24, 44),
    [System.Drawing.PointF]::new(40, 26),
    [System.Drawing.PointF]::new(40, 12)
)
$shieldPath.AddPolygon($pts)
$g.FillPath([System.Drawing.Brushes]::Firebrick, $shieldPath)
$g.DrawPath((New-Object System.Drawing.Pen([System.Drawing.Color]::OrangeRed, 1.5)), $shieldPath)

# Check mark blanco
$pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 3)
$pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$pen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
$g.DrawLine($pen, 16, 26, 22, 33)
$g.DrawLine($pen, 22, 33, 33, 18)
$pen.Dispose()

$g.Dispose()

# Convertir a ICO
$icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
$fs   = [System.IO.File]::OpenWrite("$PSScriptRoot\icon.ico")
$icon.Save($fs)
$fs.Close()
$icon.Dispose()
$bmp.Dispose()
Write-Host "Icono generado: icon.ico" -ForegroundColor Green

# Compilar
Write-Host "Compilando SecuritySuite.exe..." -ForegroundColor Cyan
Import-Module ps2exe
Invoke-ps2exe `
    -inputFile  "$PSScriptRoot\SecuritySuite.ps1" `
    -outputFile "$PSScriptRoot\SecuritySuite.exe" `
    -iconFile   "$PSScriptRoot\icon.ico" `
    -noConsole  `
    -title      "SecuritySuite" `
    -description "Suite de seguridad y privacidad para Windows" `
    -company    "EnMaNueL-G" `
    -version    "1.0.0.0"

if (Test-Path "$PSScriptRoot\SecuritySuite.exe") {
    $size = [Math]::Round((Get-Item "$PSScriptRoot\SecuritySuite.exe").Length / 1KB, 0)
    Write-Host "EXE generado: SecuritySuite.exe ($size KB)" -ForegroundColor Green

    # Crear ZIP
    $zipPath = "$PSScriptRoot\SecuritySuite-v1.0.0.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path "$PSScriptRoot\SecuritySuite.exe","$PSScriptRoot\SecuritySuite.bat" -DestinationPath $zipPath
    $zipSize = [Math]::Round((Get-Item $zipPath).Length / 1KB, 0)
    Write-Host "ZIP generado: SecuritySuite-v1.0.0.zip ($zipSize KB)" -ForegroundColor Green
} else {
    Write-Host "ERROR: No se genero el EXE" -ForegroundColor Red
    exit 1
}

Write-Host "`nBuild completado exitosamente." -ForegroundColor Green
